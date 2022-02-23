#include "operations.h"
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>


int tfs_init() {
    state_init();

    /* create root inode */
    int root = inode_create(T_DIRECTORY);
    if (root != ROOT_DIR_INUM) {
        return -1;
    }

    return 0;
}

int tfs_destroy() {
    state_destroy();
    return 0;
}

static bool valid_pathname(char const *name) {
    return name != NULL && strlen(name) > 1 && name[0] == '/';
}


int tfs_lookup(char const *name) {
    if (!valid_pathname(name)) {
        return -1;
    }

    // skip the initial '/' character
    name++;

    return find_in_dir(ROOT_DIR_INUM, name);
}

int tfs_open(char const *name, int flags) {
    int inum;
    size_t offset;

    /* Checks if the path name is valid */
    if (!valid_pathname(name)) {
        return -1;
    }

    inum = tfs_lookup(name);

    if (inum >= 0) {
        /* The file already exists */
        inode_t *inode = inode_get(inum);
        if (inode == NULL) {
            return -1;
        }

        /* Trucate (if requested) */
        if (flags & TFS_O_TRUNC) {
            if (inode->i_size > 0) {
                for (int i = 0; i < DIRECT_DATA_BLOCKS; i++) { // Freeing the direct data blocks
                    if (inode->i_data_block_direct[i] != -1 && data_block_free(inode->i_data_block_direct[i]) == -1) return -1;
                }

                if (inode->i_data_block_indirect != -1) { // Freeing indirect data blocks
                    int *data_block_content = data_block_get(inode->i_data_block_indirect);

                    for (int i = 0; i < BLOCK_SIZE / sizeof(int); i++) {
                        if (data_block_content[i] != -1 && data_block_free(data_block_content[i]) == -1) return -1;
                    }

                    if (data_block_free(inode->i_data_block_indirect) == -1) return -1;
                }
                inode->i_size = 0;
            }
        }
        /* Determine initial offset */
        if (flags & TFS_O_APPEND) {
            offset = inode->i_size;
        } else {
            offset = 0;
        }
    } else if (flags & TFS_O_CREAT) {
        /* The file doesn't exist; the flags specify that it should be created*/
        /* Create inode */
        inum = inode_create(T_FILE);
        if (inum == -1) {
            return -1;
        }
        /* Add entry in the root directory */
        if (add_dir_entry(ROOT_DIR_INUM, inum, name + 1) == -1) {
            inode_delete(inum);
            return -1;
        }
        offset = 0;
    } else {
        return -1;
    }

    /* Finally, add entry to the open file table and
     * return the corresponding handle */
    return add_to_open_file_table(inum, offset);

    /* Note: for simplification, if file was created with TFS_O_CREAT and there
     * is an error adding an entry to the open file table, the file is not
     * opened but it remains created */
}

int tfs_copy_to_external_fs(char const *source, char const *destination) { // P2
    if (tfs_lookup(source) == -1) return -1;

    int source_h = tfs_open(source, 0);
    if (source_h == -1) return -1;

    int destination_h = open(destination, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);
    if (destination_h == -1) return -1; 

    inode_t *inode = inode_get(source_h);
    void *buff = malloc(inode->i_size);

    size_t read_size = (size_t) tfs_read(source_h, buff, inode->i_size);
    if (read_size == -1) return -1;

    if (write(destination_h, buff, read_size) != read_size) return -1;

    close(destination_h);
    free(buff);
    if (tfs_close(source_h) == -1) return -1;

    return 0;
}

int tfs_close(int fhandle) { return remove_from_open_file_table(fhandle); }

ssize_t tfs_write(int fhandle, void const *buffer, size_t to_write) {
    open_file_entry_t *file = get_open_file_entry(fhandle);
    if (file == NULL) {
        return -1;
    }

    /* From the open file table entry, we get the inode */
    inode_t *inode = inode_get(file->of_inumber);
    if (inode == NULL) {
        return -1;
    }

    inode_lock(file->of_inumber);

    size_t already_written = 0;

    while (already_written < to_write) {
        
        int current_block_order = (int) (1 + file->of_offset / BLOCK_SIZE); 
        size_t of_offset_in_block = (size_t) ((int) file->of_offset - (current_block_order - 1) * BLOCK_SIZE);
        size_t write_current_loop = (to_write - already_written);

        int current_block_index = inode_get_block_index(inode, current_block_order);

        if (current_block_index == -1) { // If there isn't an allocated block, then create a new one
            if (current_block_order > 0 && current_block_order <= DIRECT_DATA_BLOCKS) { // Creating a new direct block
                current_block_index = data_block_alloc();
                inode->i_data_block_direct[current_block_order-1] = current_block_index;

            } else if (current_block_order > DIRECT_DATA_BLOCKS && current_block_order <= DIRECT_DATA_BLOCKS + BLOCK_SIZE / sizeof(int)) { // Creating a new indirect block
                if (inode->i_data_block_indirect == -1) {
                    inode->i_data_block_indirect = data_block_alloc();
                    int* indirect_block_content = data_block_get(inode->i_data_block_indirect);
                    for (int i = 0; i < BLOCK_SIZE / sizeof(int); i++) indirect_block_content[i] = -1;
                }
                
                int* indirect_block_content = data_block_get(inode->i_data_block_indirect);

                current_block_index = data_block_alloc();
                indirect_block_content[current_block_order - DIRECT_DATA_BLOCKS - 1] = current_block_index;
            }
        }

        if (current_block_index == -1) return -1;

        void *block = data_block_get(current_block_index);
        if (block == NULL) {
            return -1;
        }

        // Making sure nothing is written off-block
        if (write_current_loop > BLOCK_SIZE) write_current_loop = BLOCK_SIZE;
        if (write_current_loop + of_offset_in_block > BLOCK_SIZE) write_current_loop = BLOCK_SIZE - of_offset_in_block;

        /* Perform the actual write */
        memcpy(block + of_offset_in_block, buffer, write_current_loop);

        /* The offset associated with the file handle is
         * incremented accordingly */
        already_written += write_current_loop;
        file->of_offset += write_current_loop;
        if (file->of_offset > inode->i_size) {
            inode->i_size = file->of_offset;
        }
    }

    inode_unlock(file->of_inumber);

    return (ssize_t)already_written;
}

ssize_t tfs_read(int fhandle, void *buffer, size_t len) {
    open_file_entry_t *file = get_open_file_entry(fhandle);
    if (file == NULL) {
        return -1;
    }

    /* From the open file table entry, we get the inode */
    inode_t *inode = inode_get(file->of_inumber);
    if (inode == NULL) {
        return -1;
    }

    inode_lock(file->of_inumber);

    /* Determine how many bytes to read */
    size_t to_read = inode->i_size - file->of_offset;
    if (to_read > len) {
        to_read = len;
    }

    size_t already_read = 0;

    while (already_read < to_read) {
        int current_block_order = (int) (1 + file->of_offset / BLOCK_SIZE); 
        size_t of_offset_in_block = (size_t) ((int) file->of_offset - (current_block_order - 1) * BLOCK_SIZE);
        size_t read_current_loop = (to_read - already_read);

        int current_block_index = inode_get_block_index(inode, current_block_order);
        if (current_block_index == -1) return -1;

        void *block = data_block_get(current_block_index);
        if (block == NULL) {
            return -1;
        }
        
        // Making sure nothing is written off-block
        if (read_current_loop > BLOCK_SIZE) read_current_loop = BLOCK_SIZE;
        if (read_current_loop + of_offset_in_block > BLOCK_SIZE) read_current_loop = BLOCK_SIZE - of_offset_in_block;


        /* Perform the actual read */
        memcpy(buffer + already_read, block + of_offset_in_block, read_current_loop);
    
        /* The offset associated with the file handle is
         * incremented accordingly */
        file->of_offset += read_current_loop;
        already_read += read_current_loop;
    }

    inode_unlock(file->of_inumber);

    return (ssize_t)already_read;
}
