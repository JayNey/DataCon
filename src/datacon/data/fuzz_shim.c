/*
 * DataCon fixed libFuzzer shim (T12 改9, reviewed once; digest pinned in
 * datacon.fuzz.FUZZ_SHIM_REVIEWED_DIGEST).
 *
 * The shim is read-only repository material. It is never generated, edited or
 * specialized per case: every guided campaign links this exact file next to
 * the frozen case harness. The harness keeps its own stdin entry point; the
 * build renames that entry point to ``datacon_harness_main`` (``-Dmain=``) so
 * libFuzzer can own ``main``. For each input the shim places the bytes on file
 * descriptor 0 (a memfd), gives the harness a fresh ``stdin`` stream over it,
 * and calls the harness entry point. The harness's own stdout is discarded so
 * the fuzz log only carries libFuzzer and sanitizer output.
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

int datacon_harness_main(void);

static int datacon_input_fd = -1;

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc;
    (void)argv;
    datacon_input_fd = memfd_create("datacon-fuzz-input", 0);
    if (datacon_input_fd < 0)
        return -1;
    int devnull = open("/dev/null", O_WRONLY);
    if (devnull >= 0) {
        (void)dup2(devnull, 1);
        (void)close(devnull);
    }
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (datacon_input_fd < 0)
        return 0;
    if (ftruncate(datacon_input_fd, 0) != 0)
        return 0;
    size_t offset = 0;
    while (offset < size) {
        ssize_t written = pwrite(datacon_input_fd, data + offset, size - offset,
                                 (off_t)offset);
        if (written <= 0)
            return 0;
        offset += (size_t)written;
    }
    if (dup2(datacon_input_fd, 0) < 0)
        return 0;
    if (lseek(0, 0, SEEK_SET) != 0)
        return 0;
    int stream_fd = dup(0);
    if (stream_fd < 0)
        return 0;
    FILE *stream = fdopen(stream_fd, "r");
    if (stream == NULL) {
        (void)close(stream_fd);
        return 0;
    }
    FILE *saved = stdin;
    stdin = stream;
    (void)datacon_harness_main();
    stdin = saved;
    (void)fclose(stream);
    (void)fflush(stdout);
    return 0;
}
