#define FUSE_USE_VERSION 31
#include <fuse3/fuse.h>
#include <string.h>
#include <errno.h>

static const char *cakefs_path = "/file";

static int cakefs_getattr(const char *path, struct stat *stbuf, struct fuse_file_info *fi) {
    memset(stbuf, 0, sizeof(struct stat));
    if (strcmp(path, "/") == 0) {
        stbuf->st_mode = S_IFDIR | 0755;
        stbuf->st_nlink = 2;
    } else if (strcmp(path, cakefs_path) == 0) {
        stbuf->st_mode = S_IFREG | 0444;
        stbuf->st_nlink = 1;
        stbuf->st_size = 1024;
    } else {
        return -ENOENT;
    }
    return 0;
}

static int cakefs_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi, enum fuse_readdir_flags flags) {
    if (strcmp(path, "/") != 0)
        return -ENOENT;

    filler(buf, ".", NULL, 0, 0);
    filler(buf, "..", NULL, 0, 0);
    filler(buf, cakefs_path + 1, NULL, 0, 0);
    return 0;
}

static int cakefs_open(const char *path, struct fuse_file_info *fi) {
    if (strcmp(path, cakefs_path) != 0)
        return -ENOENT;
    return 0;
}

static int cakefs_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    if (strcmp(path, cakefs_path) != 0)
        return -ENOENT;

    const char *content = "CakeFS Content\n";
    size_t len = strlen(content);
    if (offset >= len)
        return 0;
    if (offset + size > len)
        size = len - offset;
    memcpy(buf, content + offset, size);
    return size;
}

static struct fuse_operations cakefs_oper = {
    .getattr = cakefs_getattr,
    .readdir = cakefs_readdir,
    .open = cakefs_open,
    .read = cakefs_read,
};

int main(int argc, char *argv[]) {
    return fuse_main(argc, argv, &cakefs_oper, NULL);
}
