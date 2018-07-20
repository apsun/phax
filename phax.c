/*
 * phax: a simple Cheat Engine clone for Linux using ptrace
 * 
 * Best run with a wrapper shell script for interactive searching.
 * This program is a very basic command-line utility that does not
 * preserve state across runs.
 *
 * If you get permission errors on ptrace attach, you may need to
 * run the following command:
 *
 *   sudo tee /proc/sys/kernel/yama/ptrace_scope <<< 0
 */

#define _GNU_SOURCE
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <endian.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>

#define BUFFER_SIZE 4096

typedef enum vm_flags {
    NONE = 0,
    READ = (1 << 0),
    WRITE = (1 << 1),
    EXECUTE = (1 << 2),
    SHARED = (1 << 3),
} vm_flags_t;

typedef struct vm_map {
    struct vm_map *next;
    size_t start;
    size_t end;
    vm_flags_t flags;
    char *path;
} vm_map_t;

/*
 * Converts from the maps flags string format (e.g. rw-p) to a bitwise
 * combination of flags.
 */
static vm_flags_t
parse_vm_flags(const char flags_str[5])
{
    vm_flags_t flags = NONE;
    if (flags_str[0] == 'r') flags |= READ;
    if (flags_str[1] == 'w') flags |= WRITE;
    if (flags_str[2] == 'x') flags |= EXECUTE;
    if (flags_str[3] == 's') flags |= SHARED;
    return flags;
}

/*
 * Frees a linked list of vm mappings.
 */
static void
free_vm_maps(vm_map_t *head)
{
    while (head != NULL) {
        vm_map_t *next = head->next;
        free(head->path);
        free(head);
        head = next;
    }
}

/*
 * Reads the vm mappings from /proc/<pid>/maps. Results are returned
 * as a linked list of vm_map_t structures, or NULL if the file could
 * not be read (invalid PID, OOM, etc).
 */
static vm_map_t *
get_vm_maps(pid_t pid)
{
    size_t start;
    size_t end;
    char flags_str[5];
    char path[4096];
    vm_map_t *head = NULL;
    vm_map_t **next = &head;

    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE *fp = fopen(path, "r");
    if (fp == NULL) {
        perror("fopen(maps)");
        goto cleanup;
    }

    // Format: start-end flags offset major:minor inode [path]
    while (fscanf(fp, "%zx-%zx %4s %*s %*s %*s%4095[^\n]",
        &start, &end, flags_str, path) != EOF)
    {
        vm_map_t *curr = malloc(sizeof(vm_map_t));
        if (curr == NULL) {
            perror("malloc");
            goto cleanup_err;
        }

        *next = curr;
        next = &curr->next;
        curr->next = NULL;
        curr->start = start;
        curr->end = end;
        curr->flags = parse_vm_flags(flags_str);
        curr->path = strdup(path + strspn(path, " "));
        if (curr->path == NULL) {
            perror("strdup");
            goto cleanup_err;
        }
    }

cleanup:
    fclose(fp);
    return head;

cleanup_err:
    free_vm_maps(head);
    head = NULL;
    goto cleanup;
}

/*
 * Attaches to the specified process using ptrace and waits for
 * it to stop.
 */
static int
ptrace_attach(pid_t pid)
{
    if (ptrace(PTRACE_ATTACH, pid, 0, 0) < 0) {
        perror("ptrace(ATTACH)");
        return -1;
    }

    if (waitpid(pid, NULL, 0) < 0) {
        perror("waitpid");
        return -1;
    }

    return 0;
}

/*
 * Detaches from the specified process and resumes it.
 */
static int
ptrace_detach(pid_t pid)
{
    if (ptrace(PTRACE_DETACH, pid, 0, 0) < 0) {
        perror("ptrace(DETACH)");
        return -1;
    }

    return 0;
}

/*
 * Opens the /proc/<pid>/mem file for the specified process.
 */
static int
open_mem(pid_t pid, int flags)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/mem", pid);

    int memfd;
    if ((memfd = open(path, flags)) < 0) {
        perror("open(mem)");
        return -1;
    }
    return memfd;
}

/*
 * Seeks to the specified address on the given proc mem file.
 */
static int
seek_mem(int memfd, size_t addr)
{
    if (lseek(memfd, addr, SEEK_SET) < 0) {
        perror("lseek");
        return -1;
    }
    return 0;
}

/*
 * Reads exactly nbytes from the specified file.
 */
static int
read_all(int fd, void *buf, size_t nbytes)
{
    uint8_t *bufp = buf;
    size_t offset = 0;
    while (offset < nbytes) {
        ssize_t ret = read(fd, &bufp[offset], nbytes - offset);
        if (ret < 0) {
            perror("read");
            return -1;
        } else if (ret == 0) {
            fprintf(stderr, "read: reached EOF before nbytes read\n");
            return -1;
        }
        offset += ret;
    }
    return 0;
}

/*
 * Writes exactly nbytes to the specified file.
 */
static int
write_all(int fd, const void *buf, size_t nbytes)
{
    const uint8_t *bufp = buf;
    size_t offset = 0;
    while (offset < nbytes) {
        ssize_t ret = write(fd, &bufp[offset], nbytes - offset);
        if (ret < 0) {
            perror("write");
            return -1;
        }
        offset += ret;
    }
    return 0;
}

/*
 * Repairs the endianness for a search value, copying the value in
 * correct byte order to buf.
 *
 * Currently only LE is supported so this is just a memcpy().
 */
static void
fix_endian(uint8_t *buf, uintmax_t val, size_t nbytes)
{
    memcpy(buf, &val, nbytes);
}

/*
 * Searches for the specified pattern within a specific vm mapping.
 * Prints the address of all results found.
 */
static int
search_vma(int memfd, size_t start, size_t end,
    const void *pattern, size_t pattern_size)
{
    if (seek_mem(memfd, start) < 0) {
        return -1;
    }

    // Since we need to maintain at least pattern_size - 1 bytes
    // in the buffer to handle misaligned accesses, we would end up
    // doing partial page reads unless there is enough space in the
    // buffer to hold those extra bytes plus an entire page's worth
    // of bytes.
    uint8_t buf[BUFFER_SIZE + sizeof(uintmax_t) - 1];
    size_t buf_off = 0;
    size_t file_off = 0;

    while (start + file_off < end) {
        size_t to_read = end - file_off;
        if (to_read > sizeof(buf) - buf_off) {
            to_read = sizeof(buf) - buf_off;
        }

        // Clamp to the page size for the initial read
        if (to_read > BUFFER_SIZE) {
            to_read = BUFFER_SIZE;
        }

        ssize_t ret = read(memfd, &buf[buf_off], to_read);
        if (ret < 0) {
            perror("read");
            return -1;
        }

        file_off += ret;
        buf_off += ret;

        // memmem is a GNU extension that works analogously to
        // strstr. Logic here is a bit complex: we want to make
        // sure that we don't miss any results that lie across
        // read boundaries, so always maintain at least
        // pattern_size - 1 bytes in the buffer unless we've
        // reached the end of the region.
        size_t read_off = 0;
        while (buf_off - read_off >= pattern_size) {
            void *result = memmem(&buf[read_off], buf_off - read_off, pattern, pattern_size);
            if (result == NULL) {
                ssize_t delta = buf_off - pattern_size + 1;
                if (delta >= 0 && (size_t)delta > read_off) {
                    read_off = delta;
                }
            } else {
                size_t delta = (uint8_t *)result - buf;
                printf("%p\n", (void *)(start + delta));
                read_off = delta + 1;
            }
        }

        memmove(&buf[0], &buf[read_off], buf_off - read_off);
        buf_off -= read_off;
    }

    return 0;
}

/*
 * Searches for the specified pattern within the specified process's
 * virtual memory areas. Results are printed to stdout.
 */
static int
do_search(pid_t pid, const void *pattern, size_t pattern_size)
{
    int ret = -1;
    int memfd = -1;
    vm_map_t *maps = NULL;

    if ((memfd = open_mem(pid, O_RDONLY)) < 0) {
        goto cleanup;
    }

    if ((maps = get_vm_maps(pid)) == NULL) {
        goto cleanup;
    }

    for (vm_map_t *map = maps; map != NULL; map = map->next) {
        if (map->flags & WRITE) {
            if (search_vma(memfd, map->start, map->end, pattern, pattern_size) < 0) {
                goto cleanup;
            }
        }
    }

    ret = 0;

cleanup:
    if (maps != NULL) free_vm_maps(maps);
    if (memfd >= 0) close(memfd);
    return ret;
}

/*
 * Filters a previous search. Essentially equivalent to calling
 * search again and then running comm -12 on the output, but
 * is faster since it does not search the entire address space.
 * The input is taken from stdin, and the output is written to stdout.
 */
static int
do_filter(pid_t pid, const void *pattern, size_t pattern_size)
{
    int ret = -1;
    int memfd = -1;

    if ((memfd = open_mem(pid, O_RDONLY)) < 0) {
        goto cleanup;
    }

    char buf[64];
    while (fgets(buf, sizeof(buf), stdin) != NULL) {
        size_t addr = strtoul(buf, NULL, 0);
        if (seek_mem(memfd, addr) < 0) {
            goto cleanup;
        }

        uint8_t tmp[sizeof(uintmax_t)];
        if (read_all(memfd, tmp, pattern_size) < 0) {
            goto cleanup;
        }

        if (memcmp(pattern, tmp, pattern_size) == 0) {
            printf("%p\n", (void *)addr);
        }
    }

    ret = 0;

cleanup:
    if (memfd >= 0) close(memfd);
    return ret;
}

/*
 * Writes a value to the specified process's memory. The address(es)
 * to write at are taken from stdin.
 */
static int
do_write(pid_t pid, const void *value, size_t value_size)
{
    int ret = -1;
    int memfd = -1;

    if ((memfd = open_mem(pid, O_WRONLY)) < 0) {
        goto cleanup;
    }

    char buf[64];
    while (fgets(buf, sizeof(buf), stdin) != NULL) {
        size_t addr = strtoul(buf, NULL, 0);
        if (seek_mem(memfd, addr) < 0) {
            goto cleanup;
        }

        if (write_all(memfd, value, value_size) < 0) {
            goto cleanup;
        }
    }

    ret = 0;

cleanup:
    if (memfd >= 0) close(memfd);
    return ret;
}

int
main(int argc, char **argv)
{
    if (argc != 5) {
        fprintf(stderr,
            "usage:\n"
            "  %s <pid> <type> <mode> <value>\n"
            "\n"
            "type:\n"
            "  i8/i16/i32/i64\n"
            "  u8/u16/u32/u64\n"
            "\n"
            "mode:\n"
            "  search > out.txt\n"
            "  filter < in.txt > out.txt\n"
            "  write  < in.txt\n"
            "\n"
            "examples:\n"
            "  %s `pidof hackme` i32 search 0x1234abcd > first.txt\n"
            "  %s `pidof hackme` i32 filter 0xdeadface < first.txt > second.txt\n"
            "  %s `pidof hackme` i32 write 0x41414141 < second.txt\n"
            , argv[0], argv[0], argv[0], argv[0]);
        return 1;
    }

    pid_t pid = atoi(argv[1]);
    char *type_str = argv[2];
    char *mode_str = argv[3];
    char *value_str = argv[4];

    // WARNING: ignoring errors up ahead, since handling them
    // is a massive PITA and I'm lazy. Specific stuff that lacks
    // error handling:
    //
    // - checking that type is valid
    // - checking that value is a valid number
    // - checking that value is in the range of type

    uintmax_t value;
    if (type_str[0] == 'i') {
        value = strtoll(value_str, NULL, 0);
    } else if (type_str[0] == 'u') {
        value = strtoull(value_str, NULL, 0);
    } else {
        fprintf(stderr, "Invalid type: %s\n", type_str);
        return 1;
    }

    size_t nbits = strtoul(&type_str[1], NULL, 0);
    if (nbits != 8 && nbits != 16 && nbits != 32 && nbits != 64) {
        fprintf(stderr, "Invalid type: %s\n", type_str);
        return 1;
    }

    size_t nbytes = nbits / 8;
    uint8_t needle[sizeof(uintmax_t)];
    fix_endian(needle, value, nbytes);

    if (ptrace_attach(pid) < 0) {
        return 1;
    }

    int ret;
    if (strcmp(mode_str, "search") == 0) {
        ret = do_search(pid, needle, nbytes);
    } else if (strcmp(mode_str, "filter") == 0) {
        ret = do_filter(pid, needle, nbytes);
    } else if (strcmp(mode_str, "write") == 0) {
        ret = do_write(pid, needle, nbytes);
    } else {
        fprintf(stderr, "Invalid mode: %s\n", mode_str);
        ret = -1;
    }

    if (ptrace_detach(pid) < 0) {
        return 1;
    }

    return (ret < 0) ? 1 : 0;
}
