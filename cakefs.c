#define FUSE_USE_VERSION 31
#include <fuse3/fuse.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>

static const char *cakefs_path = "/file";
// static const char *fake_content = "CakeFS Content\n"; // Remove unused variable
static char file_content[1024] = "CakeFS Content\n";  // Buffer to store content for write operations

static int cakefs_getattr(const char *path, struct stat *stbuf, struct fuse_file_info *fi) {
    memset(stbuf, 0, sizeof(struct stat));
    if (strcmp(path, "/") == 0) {
        stbuf->st_mode = S_IFDIR | 0777;
        stbuf->st_nlink = 2;
    } else if (strcmp(path, cakefs_path) == 0) {
        stbuf->st_mode = S_IFREG | 0777;
        stbuf->st_nlink = 1;
        stbuf->st_size = strlen(file_content);
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

    size_t len = strlen(file_content);
    if (offset >= len)
        return 0;
    if (offset + size > len)
        size = len - offset;
    memcpy(buf, file_content + offset, size);
    return size;
}

// Add a create function to allow new files to be created
static int cakefs_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
    if (strcmp(path, cakefs_path) == 0)
        return -EEXIST;  // If the file already exists, return an error
    printf("Creating file: %s\n", path); //debugging print statement
    return 0;
}
 
// Add a write function to allow writing data to the file
static int cakefs_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    if (strcmp(path, cakefs_path) != 0)
        return -ENOENT;

    if (offset + size > sizeof(file_content) - 1) {
        size = sizeof(file_content) - offset - 1;
    }
    memcpy(file_content + offset, buf, size);
    file_content[offset + size] = '\0';  // Null-terminate to keep it as a string

    return size;
}

// Add unlink to allow deleting the file
static int cakefs_unlink(const char *path) {
    if (strcmp(path, cakefs_path) != 0)
        return -ENOENT;

    memset(file_content, 0, sizeof(file_content));
    return 0;
}

static struct fuse_operations cakefs_oper = {
    .getattr = cakefs_getattr,
    .readdir = cakefs_readdir,
    .open = cakefs_open,
    .read = cakefs_read,
    .create = cakefs_create,  // Add create operation
    .write = cakefs_write,    // Add write operation
    .unlink = cakefs_unlink,  // Add unlink (delete) operation
};

int main(int argc, char *argv[]) {
    return fuse_main(argc, argv, &cakefs_oper, NULL);
}

