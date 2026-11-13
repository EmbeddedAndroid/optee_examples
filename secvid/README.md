# secvid: secure video with protected buffers

A Trusted Application and host side for a secure media pipeline: the TA
decrypts content into buffers of the TEE protected heap, which the host
CPU cannot read, a codec decodes or encodes them there, and the TA
hashes the result so that a test can compare it with a reference. The
host only ever handles ciphertext and DMA-buf file descriptors.

Pieces:

- `ta/`: the secvid TA. Commands (see `ta/include/secvid_ta.h`):
  DECRYPT (AES-128-CTR into a protected buffer; refused with
  `TEE_ERROR_SECURITY` when the output is not secure memory) and DIGEST
  (SHA-256 of a protected buffer). Demo shortcuts, not for a product:
  the content key is built in, every unit is decrypted from the start of
  the same CTR key stream, and DECRYPT and DIGEST return hashes of the
  plaintext (DIGEST of any range the host asks for), an oracle on it. A
  real player gets its keys from a key system, uses a fresh IV per unit
  and does not expose such commands.
- `host/main.c`: `optee_example_secvid <stream.enc> <stream.idx>`
  decrypts every unit of a stream into the protected heap and prints the
  TA's SHA-256 of each, after checking that the TA refuses to decrypt
  into ordinary host memory (`TEE_ERROR_SECURITY`).
- `host/gst/`: a GStreamer plugin with two elements:
  - `secvidsrc`: pushes each unit of a stream as a DMA-buf. `mode=tee`
    (default): the TA decrypts it into a protected-heap buffer.
    `mode=clear`: reference runs, from the XOR-stored plaintext into a
    system-heap buffer. `buffer-size` sets a minimum buffer size, for
    V4L2 queues whose buffers must be as large as their `sizeimage`.
    Buffers are not recycled: vb2 keeps a DMA-buf mapped in its V4L2
    slot until another replaces it, and with protected memory the
    hypervisor refuses to map pages into a second slot while they are
    still mapped for another, which a recycling pool smaller than the
    queue causes.
  - `secviddigestsink`: writes the SHA-256 of every buffer to a file.
    `mode=tee` (default): the TA hashes the protected buffer; the
    element never maps it. `mode=host`: the CPU hashes (reference runs).
- `scripts/secvid_pack.py`: packs an H.264 stream (split at access unit
  delimiters) or raw frames into `<prefix>.enc`, `.idx` and `.x`.

## Requirements

- OP-TEE with `CFG_SECURE_DATA_PATH=y`, `CFG_CORE_DYN_PROTMEM=y` (the
  protected memory is lent by Linux) and `CFG_CACHE_API=y` (the TA
  cleans what it writes, for non-coherent devices).
- Linux with the TEE protected-memory heap
  (`/dev/dma_heap/protected,secure-video`) and enough CMA for the pool;
  kernel headers 5.6 or newer (`linux/dma-heap.h`) to build the host.
- For secure decoding: a V4L2 codec driver that takes protected
  DMA-bufs on both queues in a secure session, and GStreamer's v4l2
  elements with `capture-dma-heap`.

## Build

As the other examples (`make` with `CROSS_COMPILE`, `TEEC_EXPORT` and
`TA_DEV_KIT_DIR`, or CMake). The plugin: `make gst` with `pkg-config`
finding `gstreamer-1.0`, `gstreamer-base-1.0` and
`gstreamer-allocators-1.0` for the target, or CMake with
`-DSECVID_GST=ON`.

## Example: secure H.264 decode

```
python3 scripts/secvid_pack.py h264 clip.h264 clip
# secure run: protected bitstream, protected frames, TA digests
gst-launch-1.0 secvidsrc location=clip.enc index=clip.idx \
    buffer-size=8388608 caps="video/x-h264,stream-format=byte-stream,alignment=au" ! \
  v4l2h264dec output-io-mode=dmabuf-import \
    capture-dma-heap=protected,secure-video \
    extra-controls="c,secure_session=1" ! \
  secviddigestsink location=secure.sha256
# reference run: the same decode in the clear, CPU digests
gst-launch-1.0 secvidsrc mode=clear location=clip.x index=clip.idx \
    buffer-size=8388608 caps="video/x-h264,stream-format=byte-stream,alignment=au" ! \
  v4l2h264dec output-io-mode=dmabuf-import capture-dma-heap=system ! \
  secviddigestsink mode=host location=clear.sha256
cmp secure.sha256 clear.sha256
```

Iris sizes its bitstream buffers for 4K (about 6.75 MiB), hence the
8 MiB `buffer-size`. `secure_session` is the control the driver exposes
for its secure sessions (here the Qualcomm Iris driver's "Secure
Session"); a driver without one cannot decode protected buffers. Run the
secure pass first: the clear pass puts the plaintext in host memory.
