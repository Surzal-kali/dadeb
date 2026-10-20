#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { DEFAULT_CHUNK = 1024 * 1024 };

static int write_file(const char *path, const uint8_t *buf, size_t len) {
	FILE *fp = fopen(path, "wb");
	if (!fp) {
		fprintf(stderr, "failed to open %s: %s\n", path, strerror(errno));
		return -1;
	}

	if (len > 0 && fwrite(buf, 1, len, fp) != len) {
		fprintf(stderr, "failed to write %s\n", path);
		fclose(fp);
		return -1;
	}

	fclose(fp);
	return 0;
}

static void fill_noise(uint8_t *buf, size_t len) {
	uint32_t x = 0x12345678u;
	for (size_t i = 0; i < len; ++i) {
		x ^= x << 13;
		x ^= x >> 17;
		x ^= x << 5;
		buf[i] = (uint8_t)(x & 0xFFu);
	}
}

static int make_in_chunk_fixture(
	const char *path,
	size_t file_len,
	size_t offset,
	const uint8_t pattern[4]
) {
	if (file_len < offset + 4) {
		fprintf(stderr, "fixture too small for pattern in %s\n", path);
		return -1;
	}

	uint8_t *buf = (uint8_t *)malloc(file_len);
	if (!buf) {
		fprintf(stderr, "allocation failed for %s\n", path);
		return -1;
	}

	fill_noise(buf, file_len);
	memcpy(buf + offset, pattern, 4);

	int rc = write_file(path, buf, file_len);
	free(buf);
	return rc;
}

static int make_split_fixture(
	const char *path,
	size_t chunk_size,
	const uint8_t pattern[4]
) {
	const size_t file_len = chunk_size + 16;
	const size_t split_at = chunk_size - 3;

	uint8_t *buf = (uint8_t *)malloc(file_len);
	if (!buf) {
		fprintf(stderr, "allocation failed for %s\n", path);
		return -1;
	}

	fill_noise(buf, file_len);
	memcpy(buf + split_at, pattern, 4);

	int rc = write_file(path, buf, file_len);
	free(buf);
	return rc;
}

int main(int argc, char **argv) {
	const uint8_t cave[4] = {0xDE, 0xAD, 0xBE, 0xEF};
	const uint8_t slope[4] = {0xBA, 0xAD, 0xF0, 0x0D};
	size_t chunk_size = DEFAULT_CHUNK;

	if (argc == 2) {
		char *end = NULL;
		unsigned long parsed = strtoul(argv[1], &end, 10);
		if (!end || *end != '\0' || parsed < 8) {
			fprintf(stderr, "Usage: %s [chunk_size_bytes>=8]\n", argv[0]);
			return 1;
		}
		chunk_size = (size_t)parsed;
	} else if (argc > 2) {
		fprintf(stderr, "Usage: %s [chunk_size_bytes>=8]\n", argv[0]);
		return 1;
	}

	if (write_file("fixture_none.bin", NULL, 0) != 0) {
		return 1;
	}

	if (make_in_chunk_fixture("fixture_cave_inchunk.bin", chunk_size + 64, 32, cave) != 0) {
		return 1;
	}

	if (make_in_chunk_fixture("fixture_slope_inchunk.bin", chunk_size + 64, 48, slope) != 0) {
		return 1;
	}

	if (make_split_fixture("fixture_cave_split.bin", chunk_size, cave) != 0) {
		return 1;
	}

	if (make_split_fixture("fixture_slope_split.bin", chunk_size, slope) != 0) {
		return 1;
	}

	printf("generated fixtures with chunk_size=%zu\n", chunk_size);
	printf("- fixture_none.bin\n");
	printf("- fixture_cave_inchunk.bin\n");
	printf("- fixture_slope_inchunk.bin\n");
	printf("- fixture_cave_split.bin\n");
	printf("- fixture_slope_split.bin\n");
	return 0;
}
