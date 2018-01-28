/*
	FUSE: Filesystem in Userspace
	Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

	This program can be distributed under the terms of the GNU GPL.
	See the file COPYING.
*/

/*
* Uncomment the CS1550_DEBUG
* line for some HEAVY debug messages
*/
#define CS1550_DEBUG


#define	FUSE_USE_VERSION 26

#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>

//size of a disk block
#define	BLOCK_SIZE 512

//we'll use 8.3 filenames
#define	MAX_FILENAME 8
#define	MAX_EXTENSION 3


//How many files can there be in one directory?
#define MAX_FILES_IN_DIR (BLOCK_SIZE - sizeof(int)) / ((MAX_FILENAME + 1) + (MAX_EXTENSION + 1) + sizeof(size_t) + sizeof(long))

// My FAT tables can be different sizes
// FAT_TABLE_SIZE 64 allows ~8MB file systems - 2 byte entries
#define FAT_TABLE_BLOCK_SIZE 64
#define FAT_TABLE_ENTRY_SIZE 2 // int
#define FAT_ENTRIES_PER_BLOCK (BLOCK_SIZE/FAT_TABLE_ENTRY_SIZE) // 256
#define MAX_FAT_ENTRIES (FAT_TABLE_BLOCK_SIZE*FAT_ENTRIES_PER_BLOCK) // 256*64 = 16384



#define FAT_SENTINEL 0
#define EOF -1


//The attribute packed means to not align these things
struct cs1550_directory_entry
{
	int nFiles;	//How many files are in this directory.
				//Needs to be less than MAX_FILES_IN_DIR

	struct cs1550_file_directory
	{
		char fname[MAX_FILENAME + 1];	//filename (plus space for nul)
		char fext[MAX_EXTENSION + 1];	//extension (plus space for nul)
		size_t fsize;					//file size
		long nStartBlock;				//where the first block is on disk
	} __attribute__((packed)) files[MAX_FILES_IN_DIR];	//There is an array of these

	//This is some space to get this to be exactly the size of the disk block.
	//Don't use it for anything.  
	char padding[BLOCK_SIZE - MAX_FILES_IN_DIR * sizeof(struct cs1550_file_directory) - sizeof(int)];
};

typedef struct cs1550_root_directory cs1550_root_directory;

#define MAX_DIRS_IN_ROOT (BLOCK_SIZE - sizeof(int)) / ((MAX_FILENAME + 1) + sizeof(long))
#define FAT_TABLE_2_OFFSET MAX_DIRS_IN_ROOT + 1

struct cs1550_root_directory
{
	int nDirectories;	//How many subdirectories are in the root
						//Needs to be less than MAX_DIRS_IN_ROOT
	struct cs1550_directory
	{
		char dname[MAX_FILENAME + 1];	//directory name (plus space for nul)
		long nStartBlock;				//where the directory block is on disk
	} __attribute__((packed)) directories[MAX_DIRS_IN_ROOT];	//There is an array of these

	//This is some space to get this to be exactly the size of the disk block.
	//Don't use it for anything.  
	char padding[BLOCK_SIZE - MAX_DIRS_IN_ROOT * sizeof(struct cs1550_directory) - sizeof(int)];
};

typedef struct cs1550_directory_entry cs1550_directory_entry;

//How much data can one block hold?
#define	MAX_DATA_IN_BLOCK (BLOCK_SIZE)

struct cs1550_disk_block
{
	//All of the space in the block can be used for actual data
	//storage.
	char data[MAX_DATA_IN_BLOCK];
};

typedef struct cs1550_disk_block cs1550_disk_block;

#define MAX_FAT_ENTRIES (BLOCK_SIZE/sizeof(short))

struct cs1550_file_alloc_table_block {
	short table[MAX_FAT_ENTRIES];
};

typedef struct cs1550_file_alloc_table_block cs1550_fat_block;

/*
 * Called whenever the system wants to know the file attributes, including
 * simply whether the file exists or not. 
 *
 * man -s 2 stat will show the fields of a stat structure
 */

static long file_exists(cs1550_directory_entry *dir, char *filename, char *extension, long *start_block, size_t * fsize)
{
	// Guarantees 0's incase programmer forgot to zero out start_block and fsize
	*start_block = 0;
	*fsize = 0;
	// Block is first, size is second
	int i = 0;
	for(i = 0; i < MAX_FILES_IN_DIR; i++)
	{
		if(!strcmp(dir->files[i].fname, filename) && !strcmp(dir->files[i].fext, extension))
		{
			*start_block = dir->files[i].nStartBlock;
			*fsize = dir->files[i].fsize;
		}
	}
	return start_block;
}

// Writes a specific block to the .disk file
static int write_to_block(cs1550_disk_block *buffer, long blockID)
{
	int ret = 1;
	FILE *file = fopen(".disk", "rb+");
	fseek(file, MAX_DATA_IN_BLOCK * blockID, SEEK_SET);
	
	if(!fwrite(buffer, sizeof(cs1550_disk_block), 1, file))
	{
		ret = 0;
		printf("[ERROR] [write_to_block] : fwrite in write_to_block returned failed status\n");
	}
	#ifdef CS1550_DEBUG
	else
	{
		printf("[write_to_block] : Write successful!\n");
	}
	#endif
	fclose(file);
	return ret;
}

static long file_update_size(cs1550_directory_entry *dir, char *filename, char *extension, size_t fsize)
{
	// Block is first, size is second
	int i = 0;
	for(i = 0; i < MAX_FILES_IN_DIR; i++)
	{
		if(!strcmp(dir->files[i].fname, filename) && !strcmp(dir->files[i].fext, extension))
		{
			dir->files[i].fsize = fsize;
			return 0; // successful
		}
	}
	return -1; // not successful
}

static int write_file_block(cs1550_disk_block *buffer, long nStartBlock)
{
	int block_to_write = FAT_TABLE_2_OFFSET + nStartBlock - 1; // Must subtract 1 because we're off by 1 for sentinel of 0
	return write_to_block(buffer, block_to_write);
}

static int load_fat(char *fat_pointer)
{
	int fat_blocks_read;
	FILE *file = fopen(".disk", "rb");
	
	// Seek & read relevant blocks
	fseek(file, MAX_DATA_IN_BLOCK * FAT_TABLE_2_OFFSET, SEEK_SET);
	fread(fat_pointer, sizeof(cs1550_disk_block), FAT_TABLE_BLOCK_SIZE, file); // Read an entire FAT that spans multiple blocks
	
	fat_blocks_read = FAT_TABLE_BLOCK_SIZE;
	
	#ifdef CS1550_DEBUG
		printf("[load_fat] : Read %d FAT blocks into memory\n", fat_blocks_read);
	#endif
	
	fclose(file);
	return fat_blocks_read;
}

static int write_fat(char *fat_pointer)
{
	int fat_blocks_wrote;
	FILE *file = fopen(".disk", "r+b");
	
	// Seek & read relevant blocks
	fseek(file, MAX_DATA_IN_BLOCK * FAT_TABLE_2_OFFSET, SEEK_SET);
	fwrite(fat_pointer, sizeof(cs1550_disk_block), FAT_TABLE_BLOCK_SIZE, file); // Read an entire FAT that spans multiple blocks
	
	fat_blocks_wrote = FAT_TABLE_BLOCK_SIZE;
	
	#ifdef CS1550_DEBUG
		printf("[write_fat] : Read %d FAT blocks into memory\n", fat_blocks_wrote);
	#endif
	
	fclose(file);
	return fat_blocks_wrote;
}

// Loads blocks into memory buffer passed in (using block ID)
static int load_block(cs1550_disk_block *buffer, long blockID)
{
	#ifdef CS1550_DEBUG
		printf("[load_block] : blockID = %d\n", blockID);
	#endif
	int ret = 1;
	if (blockID >= 0) {
		FILE *file = fopen(".disk", "rb");
		fseek(file, MAX_DATA_IN_BLOCK * blockID, SEEK_SET);
		if(!fread((char *)buffer, sizeof(cs1550_disk_block), 1, file))
		{
			ret = 0;
			printf("[ERROR]: [load_block] : fread in load_block returned failed status\n");
		}
		// Close file
		fclose(file);
	} else {
		printf("!!! ERROR at load_block - negative value");
		ret = 0;
	}
	#ifdef CS1550_DEBUG
		printf("[load_block] : Returning ret %d\n", ret);
	#endif
	return ret; 
}

static int load_file_block(cs1550_disk_block *buffer, long nStartBlock)
{
	int block_to_load = FAT_TABLE_2_OFFSET + nStartBlock - 1; // Must subtract 1 because we're off by 1 for sentinel of 0
	return load_block(buffer, block_to_load);
}

// Loads blocks into memory buffer passed in (using block ID)
static int load_block_by_address(cs1550_disk_block *buffer, long block_address)
{
	#ifdef CS1550_DEBUG
		printf("[load_block_by_address] : blockID = %d\n", block_address);
	#endif
	int ret = 1;
	
	if (! (block_address % MAX_DATA_IN_BLOCK) ) { // even block
		FILE *file = fopen(".disk", "rb");
		fseek(file, block_address, SEEK_SET);
		if(!fread((char *)buffer, sizeof(cs1550_disk_block), 1, file))
		{
			ret = 0;
			printf("[ERROR]: [load_block] : fread in load_block returned failed status\n");
		}
		// Close file
		fclose(file);
	} else {
		printf("!!! ERROR at load_block - not on block boundary");
		ret = 0;
	}
	return ret; 
}

static int get_fat_table_entry(int fat_table_index)
{
	// Figure out what block we need on and retrive data from that block
	int fat_table_fs_block = (fat_table_index-1) / FAT_ENTRIES_PER_BLOCK; // 128 per block - figure out what block we're on
	int block_address_offset = ((fat_table_index-1) % FAT_ENTRIES_PER_BLOCK); // Gets offset in block
	#ifdef CS1550_DEBUG
		printf("[get_fat_table_entry] : Retrieving entry %d at FAT block %d offset %d\n", fat_table_index, fat_table_fs_block, block_address_offset);
	#endif
	int block = fat_table_fs_block + FAT_TABLE_2_OFFSET; // FAT starts at block 30 (0 is root, 1-29 are subdirs)
	
	cs1550_fat_block db;
	load_block((cs1550_disk_block *)&db, block);
	
	int entry = db.table[block_address_offset]; // Should load appropriate integer via pointer arithmetic
	#ifdef CS1550_DEBUG
		printf("[get_fat_table_entry] : Returning entry %d\n", entry);
	#endif
	return entry;
}

static int set_fat_table_entry(int fat_table_index, int value)
{
	// Figure out what block we need on and retrive data from that block
	int fat_table_fs_block = (fat_table_index-1) / FAT_ENTRIES_PER_BLOCK; // 128 per block - figure out what block we're on
	int block_address_offset = ((fat_table_index-1) % FAT_ENTRIES_PER_BLOCK); // Gets offset in block
	#ifdef CS1550_DEBUG
		printf("[set_fat_table_entry] : Interpreted  FATI %d at FAT block %d offset %d\n", fat_table_index, fat_table_fs_block, block_address_offset);
	#endif
	int block = fat_table_fs_block + FAT_TABLE_2_OFFSET; // FAT starts at block 30 (0 is root, 1-29 are subdirs)
	
	cs1550_fat_block db;
	load_block((cs1550_disk_block *)&db, block);
	
	db.table[block_address_offset] = value; // Should appropriately write value
	write_to_block((cs1550_disk_block *)&db, block);
	#ifdef CS1550_DEBUG
		printf("[set_fat_table_entry] : Wrote value %d to fat_table index %d (real index %d)\n", db.table[block_address_offset], fat_table_index, fat_table_index-1);
	#endif
	return 0;
}

static int get_max_disk_size()
{
	FILE *file = fopen(".disk", "rb");
	fseek(file, 0L, SEEK_END);
	int size = ftell(file);
	fclose(file);
	return size;
}

// Finds the next empty FAT block by hunting through the FAT entries
static int find_next_empty_fat_block()
{	
	// Make room for disk block
	cs1550_fat_block db;
	
	int bi = 0; // Iterates blocks we've tried
	int found = 0; // Tracks whether we found an empty block or not
	int entry = 0;
	
	int max_disk_size = get_max_disk_size();
	#ifdef CS1550_DEBUG
		printf("[find_next_empty_fat_block] : Setting size limit of %d\n", max_disk_size);
	#endif
	
	// This while statement should allow iteration while we are still within range of our disk in terms of the fat table blocks
	while(!found && (( (FAT_TABLE_2_OFFSET + bi) * BLOCK_SIZE) + ((BLOCK_SIZE * FAT_ENTRIES_PER_BLOCK) * bi-1)  ) < max_disk_size) {
		// Load FAT table block
		load_block((cs1550_disk_block *)&db, FAT_TABLE_2_OFFSET + bi);
		int i = 0;
		// While we haven't exceeded disk size and still can't find it
		while(!found && i < FAT_ENTRIES_PER_BLOCK && (max_disk_size - (((FAT_TABLE_2_OFFSET + bi) * BLOCK_SIZE) + ((BLOCK_SIZE * FAT_ENTRIES_PER_BLOCK) * bi-1) + BLOCK_SIZE * i) > 0)) {
			#ifdef CS1550_DEBUG
				printf("[find_next_empty_fat_block] : bi %d i %d is %d\n", bi, i, db.table[i]);
			#endif
			// If this particular FAT entry matches the FAT no file associated sentinel value
			if(db.table[i] == FAT_SENTINEL)
			{
				#ifdef CS1550_DEBUG
					printf("[find_next_empty_fat_block] : Found block at bi %d index %d\n", bi, i);
				#endif
				found = 1;
				entry = i + (bi * FAT_ENTRIES_PER_BLOCK) + 1; // Return entry index (+1 because 0 is our sentinel value)
			}
			i++;
		}
		bi++;
	}
	#ifdef CS1550_DEBUG
		printf("[find_next_empty_fat_block] : Returning entry %d\n", entry);
	#endif
	return entry;
}

// Returns the starting block of a subdirectory, or if it doesn't exist, 0
static int subdirectory_exists(char *directory) {
	// Existential condition
	int at_block = 0;
	
	// Read root directory into memory from load_block 0
	cs1550_root_directory root;
	#ifdef CS1550_DEBUG
		printf("[subdirectory_exists] : Loading root block from .disk file");
	#endif
	load_block((cs1550_disk_block *)&root, 0);
	#ifdef CS1550_DEBUG
		printf("[subdirectory_exists] : Block load completed. Attempting to find directory: %s\n", directory);
		fflush(stdout);
	#endif
	
	// Iterate directories to see if the subdirectory exists
	int i = 0;
	for (i = 0; i < MAX_DIRS_IN_ROOT; i++)
	{
		#ifdef CS1550_DEBUG
			printf("[subdirectory_exists] : Iterating %s\n", root.directories[i].dname);
		#endif
		if (strcmp(root.directories[i].dname, directory) == 0)
		{
			at_block = i + 1; // If we matched a directory, then return what block it's at.
			#ifdef CS1550_DEBUG
				printf("[subdirectory_exists] : CS1550 Directory %s FOUND at start block %d\n", root.directories[i].dname, root.directories[i].nStartBlock);
			#endif
			break;
		}
	}
	
	#ifdef CS1550_DEBUG
		printf("[subdirectory_exists] : Returning at_block %d\n", at_block);
		fflush(stdout);
	#endif
	return at_block;
}


// Handles memset 0 of all extracting fields, then inputs relevant path information
static int extract_from_path(const char *path, char *directory, char *filename, char *extension)
{
		// Memset char arrays to all 0's
		memset(directory, 0, MAX_FILENAME + 1);
		memset(filename, 0, MAX_FILENAME + 1);
		memset(extension, 0, MAX_EXTENSION + 1);

		// Scan path for directory, filename, and extension
		int ret = sscanf(path, "/%[^/]/%[^.].%s", directory, filename, extension);
		return ret; // Return how many of the fields got filled out
}
 
static int cs1550_getattr(const char *path, struct stat *stbuf)
{
	int res = 0;

	memset(stbuf, 0, sizeof(struct stat));
	#ifdef CS1550_DEBUG
		printf("[getattr] : >> path=%s\n", path);
	#endif
	//is path the root dir?
	if (strcmp(path, "/") == 0)
	{
		stbuf->st_mode = S_IFDIR | 0755;
		stbuf->st_nlink = 2;
	} 
	else if (path[0] == '/')
	{
		// Stack space for each field
		char directory[MAX_FILENAME + 1];
		char filename[MAX_FILENAME + 1];
		char extension[MAX_EXTENSION + 1];
		
		// Use res as a temporary read for how many fields we read from extract_from_path
		res = extract_from_path(path, directory, filename, extension);
				
		#ifdef CS1550_DEBUG
			printf("[getattr] : Directory: %s\tFname: %s\tExt: \t%s\tRet: %d\n", directory, filename, extension, res);
			if(strcmp(directory,"") == 0) {
				printf("[getattr] : Directory empty\n");
			}
			if(strcmp(filename,"") == 0) {
				printf("[getattr] : Filename empty\n");
			}
			if(strcmp(extension,"") == 0) {
				printf("[getattr] : Extension empty\n");
			}
		#endif
		
		int subdir = subdirectory_exists(directory);
		if(subdir > 0) // If subdirectory exists
		{
			#ifdef CS1550_DEBUG
				printf("[getattr] : Subdirectory exists.\n");
			#endif
			if(res == 1)
			{
				stbuf->st_mode = S_IFDIR | 0755;
				stbuf->st_nlink = 2;
				res = 0; //no error
			}
			else
			{
				// Get directory information
				cs1550_directory_entry dir;
				#ifdef CS1550_DEBUG
					printf("[getattr] : Load block\n");
				#endif
				if(!load_block((cs1550_disk_block *)&dir, subdir))
				{
					printf("[ERROR]: [getattr] : Something went wrong loading block %d\n", subdir);
				}
				// Create stack variables for file existence check
				long start_block;
				size_t fsize;
				file_exists(&dir, filename, extension, &start_block, &fsize);
				if (start_block > 0) // If the file exists (has a starting block and size)
				{
					//regular file, probably want to be read and write
					stbuf->st_mode = S_IFREG | 0666; 
					stbuf->st_nlink = 1; //file links
					stbuf->st_size = (size_t)fsize; //file size - make sure you replace with real size!
					res = 0; // no error
				}
				else
				{
					#ifdef CS1550_DEBUG
						printf("[getattr] : Start block was not >0 - start block %d - Returning -ENOENT\n", start_block);
					#endif
					res = -ENOENT;
				}
			}
		}
		else // If the subdirectory doesn't exist, we don't have to worry about anything else.
		{
			res = -ENOENT;
		}
	}
	else // File not accessed from ROOT
	{
		res = -ENOENT;	
	}
	#ifdef CS1550_DEBUG
		printf("[getattr] : Returning value : %d\n", res);
	#endif
	return res;
}

/* 
 * Called whenever the contents of a directory are desired. Could be from an 'ls'
 * or could even be when a user hits TAB to do autocompletion
 */
static int cs1550_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
			 off_t offset, struct fuse_file_info *fi)
{
	#ifdef CS1550_DEBUG
		printf("[readdir] : ...was called at all...\n");
	#endif
	//Since we're building with -Wall (all warnings reported) we need
	//to "use" every parameter, so let's just cast them to void to
	//satisfy the compiler
	(void) offset;
	(void) fi;

	// Store the first block into a buffer
	char directory[MAX_FILENAME + 1];
	char filename[MAX_FILENAME + 1];
	char extension[MAX_EXTENSION + 1];
	
	// Use res as a temporary read for how many fields we read from extract_from_path
	int res = extract_from_path(path, directory, filename, extension);

	if (strcmp(path, "/") != 0) { // Not root?
		if (path[0] == '/') // Funny thing - scratched my head for a while because I was comparing a char with a string literal "/" :)
		{
			#ifdef CS1550_DEBUG
				printf("[readdir] : Performing read of subdirectory\n");
			#endif
			// Find where the subdirectory is located on disk, if at all
			int offset = subdirectory_exists(directory);
			if (offset == 0) { // Subdirectory doesn't exist.
				#ifdef CS1550_DEBUG
					printf("[readdir] : Subdirectory doesn't exist, returning -ENOENT\n");
				#endif
				return -ENOENT;
			}
			
			// Load the subdirectory from disk if we haven't already exited
			#ifdef CS1550_DEBUG
				printf("[readdir] : Subdirectory found, continuing read of subdirectory\n");
			#endif
			
			cs1550_directory_entry dir;
			load_block((cs1550_disk_block *)&dir, offset);
			// Begin listing directories
			
			filler(buf, ".", NULL, 0);
			filler(buf, "..", NULL, 0);
			
			int i = 0;
			char oversized_buffer[32]; // :)
			
			// Iterate file list 
			// This ASSUMES there will never be a deletion
			for(i = 0; i < dir.nFiles; i++)
			{
				memset(oversized_buffer, 0, 32);
				#ifdef CS1550_DEBUG
					printf("[readdir] : Iterating i %d\t", i);
				#endif
				int j;
				int k = 0;
				for(j = 0; j < strlen(dir.files[i].fname); j++)
				{
					oversized_buffer[k] = dir.files[i].fname[j];
					k++;
				}
				if (strcmp(dir.files[i].fext, "") != 0)
				{
					#ifdef CS1550_DEBUG
						printf(" ...added dot... ", i);
					#endif
					oversized_buffer[k] = '.';
					k++;
				}
				for(j = 0; j < strlen(dir.files[i].fext); j++)
				{
					oversized_buffer[k] = dir.files[i].fext[j];
					k++;
				}
				#ifdef CS1550_DEBUG
					printf("%s\n", oversized_buffer);
				#endif
				filler(buf, oversized_buffer, NULL, 0);
			}
		}
		else
		{
			#ifdef CS1550_DEBUG
				printf("[readdir] : File not found. Returning -ENOENT\n  -!> path \"%s\"\n", path);
			#endif
			return -ENOENT;
		}
	}
	else
	{ // ROOT?
		#ifdef CS1550_DEBUG
			printf("[readdir] : Reading from root\n");
		#endif
		filler(buf, ".", NULL, 0);

		#ifdef CS1550_DEBUG
			printf("[readdir] : Loading block\n");
		#endif
		// Get root struct from disk
		cs1550_root_directory root; 
		load_block((cs1550_disk_block *)&root, 0);
		
		int i = 0;
		for (i = 0; i < root.nDirectories; i++)
		{
			filler(buf, root.directories[i].dname, NULL, 0);
		}
	}
	//the filler function allows us to add entries to the listing
	//read the fuse.h file for a description (in the ../include dir)

	/*
	//add the user stuff (subdirs or files)
	//the +1 skips the leading '/' on the filenames
	filler(buf, newpath + 1, NULL, 0);
	*/
	return 0;
}

/* 
 * Creates a directory. We can ignore mode since we're not dealing with
 * permissions, as long as getattr returns appropriate ones for us.
 */
static int cs1550_mkdir(const char *path, mode_t mode)
{
	#ifdef CS1550_DEBUG
		printf("[mkdir] : >> path=%s\n", path);
	#endif
	(void) path;
	(void) mode;
	
	// Stack space for each field
	char directory[MAX_FILENAME + 1];
	char filename[MAX_FILENAME + 1];
	char extension[MAX_EXTENSION + 1];
	
	int ret = extract_from_path(path, directory, filename, extension);
	
	int subdir = subdirectory_exists(directory);
	
	#ifdef CS1550_DEBUG
		printf("[mkdir] : ret: %d\tsubdir: %d\n", ret, subdir);
	#endif
	if(ret > 1) // If we have more than a single subdirectory in the path
	{
		#ifdef CS1550_DEBUG
			printf("[mkdir] : Parsed fields > 1! Returning -EPERM\n");
		#endif
		return -EPERM;
	}	
	else if (subdir > 0) // If the file exists
	{
		#ifdef CS1550_DEBUG
			printf("[mkdir] : File exists! Returning -EEXIST\n");
		#endif
		return -EEXIST;
	}
	else
	{
		if (strlen(directory) <= 8)
		{
			cs1550_root_directory root;
			#ifdef CS1550_DEBUG
				printf("[mkdir] : Load block\n");
			#endif
			load_block((cs1550_disk_block *)&root, 0);
			
			int curr = root.nDirectories;
			#ifdef CS1550_DEBUG
				printf("[mkdir] : Number of directories in root: %d\n", curr);
			#endif
			if(curr == MAX_DIRS_IN_ROOT)
			{ // Can't add any more directories!
				#ifdef CS1550_DEBUG
					printf("[mkdir] : curr == MAX_DIRS_IN_ROOT ! Returning -EPERM\n");
				#endif
				return -EPERM;
			}
			
			// Update number of directories
			root.nDirectories = curr + 1;
			#ifdef CS1550_DEBUG
				printf("[mkdir] : Updated root struct nDirectories to %d\n", root.nDirectories);
			#endif			

			// Write directory name and 
			strcpy(root.directories[curr].dname, directory);
			root.directories[curr].nStartBlock = (long)curr + 1; // watch!
			#ifdef CS1550_DEBUG
				printf("[mkdir] : Updated root struct dname and nStartBlock\n");
				printf("\tdname: %s\n\tnStartBlock: %d", root.directories[curr].dname, root.directories[curr].nStartBlock);
			#endif
			write_to_block((cs1550_disk_block *)&root, 0);
			#ifdef CS1550_DEBUG
				printf("[mkdir] : Finished writing to block");
			#endif
		}
		else
		{
			#ifdef CS1550_DEBUG
				printf("[mkdir] : Directory length > 8! Returning -ENAMETOOLONG\n");
			#endif
			return -ENAMETOOLONG;
		}
	}
	#ifdef CS1550_DEBUG
		printf("[mkdir] : MKDIR exiting with exit code 0");
	#endif
	return 0;
}

/* 
 * Removes a directory.
 */
static int cs1550_rmdir(const char *path)
{
	(void) path;
    return 0;
}

/* 
 * Does the actual creation of a file. Mode and dev can be ignored.
 *
 */
static int cs1550_mknod(const char *path, mode_t mode, dev_t dev)
{
	#ifdef CS1550_DEBUG
		printf("[mknod] : Path: %s\n", path);
	#endif
	char directory[MAX_FILENAME + 1];
    char filename[MAX_FILENAME + 1];
    char extension[MAX_EXTENSION + 1];
	(void) mode;
	(void) dev;
	
	int ret = extract_from_path(path, directory, filename, extension);

	if (ret < 2)
	{
		#ifdef CS1550_DEBUG
			printf("[mknod] : Returning -EPERM because trying to create file in root\n");
		#endif
		return -EPERM;
	}
	else
	{
		#ifdef CS1550_DEBUG
			printf("[mknod] : Directory: %s\tFilename: %s\tExtension: %s\n", directory, filename, extension);
		#endif
		int dir_block_offset = subdirectory_exists(directory); // Get directory block
		if(!dir_block_offset)
		{
			printf("[mknod] : There was a problem - dir_block_offset is 0!\n");
			return -EPERM;
		}
		// Load directory onto stack
		cs1550_directory_entry dir;
		load_block(&dir, dir_block_offset);
		// Load file, if it exists
		long f_start_block = 0;
		size_t fsize = 0;
		file_exists(&dir, filename, extension, &f_start_block, &fsize);
		#ifdef CS1550_DEBUG
			printf("[mknod] : strlen(filename): %d   strlen(extension): %d\n", strlen(filename), strlen(extension));
		#endif
		if(f_start_block != 0)
		{
			#ifdef CS1550_DEBUG
				printf("[mknod] : File exists! Returning -EEXIST");
			#endif
			return -EEXIST;
		}
		else if (dir.nFiles >= MAX_FILES_IN_DIR) // >= just for safety
		{
			#ifdef CS1550_DEBUG
				printf("[mknod] : MAX_FILES_IN_DIR reached\n");
			#endif
			return -EPERM;
		}
		else if (strlen(filename) > 8 || strlen(extension) > 3)
		{
			#ifdef CS1550_DEBUG
				printf("[mknod] : Filename/extension too long - returning -EPERM");
			#endif
			return -EPERM;
		}
		else
		{
			#ifdef CS1550_DEBUG
				printf("[mknod] : Writing location to next available index\n");
			#endif
			// Since we aren't deleting files, files are to be added in sequential order
			strcpy(dir.files[dir.nFiles].fname, filename);
			strcpy(dir.files[dir.nFiles].fext, extension);
			dir.files[dir.nFiles].fsize = 0; // Not making?
			dir.files[dir.nFiles].nStartBlock = find_next_empty_fat_block();
			#ifdef CS1550_DEBUG
				printf("[mknod] : Set file %s.%s to nStartBlock %d\n", dir.files[dir.nFiles].fname, dir.files[dir.nFiles].fext, dir.files[dir.nFiles].nStartBlock);
			#endif
			set_fat_table_entry(dir.files[dir.nFiles].nStartBlock, EOF); // Since new file, no data has been written - write EOF
			dir.nFiles += 1; // Increment number of files
			write_to_block((cs1550_disk_block *)&dir, dir_block_offset);
		}
	}
	return 0;
}

/*
 * Deletes a file
 */
static int cs1550_unlink(const char *path)
{
    (void) path;

    return 0;
}

/* 
 * Read size bytes from file into buf starting from offset
 *
 */
static int cs1550_read(const char *path, char *buf, size_t size, off_t offset,
			  struct fuse_file_info *fi)
{
	#ifdef CS1550_DEBUG
		printf("[read] : Path: %s\n[read] : Size: %d\n[read] : Offset: %d\n", path, size, offset);
	#endif
	(void) buf;
	(void) offset;
	(void) fi;
	(void) path;
	
	char directory[MAX_FILENAME + 1];
    char filename[MAX_FILENAME + 1];
    char extension[MAX_EXTENSION + 1];
	
	int ret = extract_from_path(path, directory, filename, extension);
	
	int i = 0;
	// Check path
	if (ret < 2)
	{
		#ifdef CS1550_DEBUG
			printf("[read] : Returning -EISDIR because trying to create file in root\n");
		#endif
		return -EISDIR;
	}
	else
	{
		#ifdef CS1550_DEBUG
			printf("[read] : Directory: %s\tFilename: %s\tExtension: %s\n", directory, filename, extension);
		#endif
		
		// Load subdirectory (assuming that directory exists)
		int subdir_at = subdirectory_exists(directory);
		cs1550_directory_entry dir;
		load_block(&dir, subdir_at);
		
		
		long fstart_block = 0;
		size_t fsize = 0;
		
		file_exists(&dir, filename, extension, &fstart_block, &fsize);
		if(!fstart_block)
		{
			return -EEXIST;
		}
		if(!fsize)
		{
			return 0; // Reading 0? Return 0. No buffer manipulation
		}
		if(offset > fsize)
		{
			return 0; // We've read 0 bytes because those bytes aren't in the file
		}
		
		// !-- ALL FAT TABLE [subscripts] MUST BE -1 (off by one) --!
		// Load entire fat table for FAT traversals
		short fat_table[FAT_ENTRIES_PER_BLOCK * FAT_TABLE_BLOCK_SIZE];
		load_fat(&fat_table);
		
		int curr_fpos = 0;
		int curr_fat_block = fstart_block;
		int curr_sequential_block = 0;
		// Line up block offset
		while(curr_fpos < offset)
		{
			if(offset - curr_fpos >= 0) // <--   >= 0 ?? could be a problem - test
			{
				curr_fpos += 512;
				curr_fat_block = fat_table[curr_fat_block - 1]; // Get next occurring block
				curr_sequential_block++;
			}
			else
			{
				curr_fpos++; // Increment until we get to where we need to be
			}
		}
		
		#ifdef CS1550_DEBUG
			printf("[read] : Loading first file block\n");
		#endif
		// Load file block
		cs1550_disk_block file_data_block;
		load_file_block(&file_data_block, curr_fat_block);
		
		// File should be lined up as necessary - now copy from buffer
		while(curr_fat_block != -1 && curr_fpos < fsize)
		{
			// Do we need to increment the file block?
			if( (curr_fpos / MAX_DATA_IN_BLOCK) > curr_sequential_block)
			{
				#ifdef CS1550_DEBUG
					printf("\n[read] : curr/MDIB > curr_seq - going from curr_fat_block %d to", curr_fat_block);
				#endif
				curr_fat_block = fat_table[curr_fat_block - 1]; // Get next occurring block
				#ifdef CS1550_DEBUG
					printf("%d\n", curr_fat_block);
				#endif
				load_file_block(&file_data_block, curr_fat_block); // Load block from disk
				curr_sequential_block++;
			}
			
			buf[i] = file_data_block.data[curr_fpos % MAX_DATA_IN_BLOCK]; // Copy to buffer byte by byte
			#ifdef CS1550_DEBUG
				printf("[read] : Reading %c into buffer\n", file_data_block.data[curr_fpos % MAX_DATA_IN_BLOCK]);
			#endif
			i++;
			curr_fpos++;
		}
	}
	//read in data
	//set size and return, or error

	size = i;

	return size;
}

/* 
 * Write size bytes from buf into file starting from offset
 *
 */
static int cs1550_write(const char *path, const char *buf, size_t size, 
			  off_t offset, struct fuse_file_info *fi)
{
	#ifdef CS1550_DEBUG
		printf("[write] : Path: %s\n[write] : Size: %d\n[write] : Offset: %d\n", path, size, offset);
	#endif
	(void) buf;
	(void) offset;
	(void) fi;
	(void) path;

	char directory[MAX_FILENAME + 1];
    char filename[MAX_FILENAME + 1];
    char extension[MAX_EXTENSION + 1];
	
	int ret = extract_from_path(path, directory, filename, extension);

	// Check path
	if (ret < 2)
	{
		#ifdef CS1550_DEBUG
			printf("[write] : Returning -EPERM because trying to create file in root\n");
		#endif
		return -EPERM;
	}
	else
	{
		#ifdef CS1550_DEBUG
			printf("[write] : Directory: %s\tFilename: %s\tExtension: %s\n", directory, filename, extension);
		#endif
		
		// Load subdirectory (assuming that directory exists)
		int subdir_at = subdirectory_exists(directory);
		cs1550_directory_entry dir;
		load_block(&dir, subdir_at);
		
		
		long fstart_block = 0;
		size_t fsize = 0;
		
		file_exists(&dir, filename, extension, &fstart_block, &fsize);
		
		// Check size > 0
		if(size == 0) return size; // Return 0 ? Why write 0 bytes?
		//check that offset is <= to the file size
		if(offset > fsize)
		{
			#ifdef CS1550_DEBUG
				printf("[write] : offset > fsize - returning -EFBIG");
			#endif
			return -EFBIG;
		}
		// How many blocks does our file span?
		int file_curr_blocks = (fsize/MAX_DATA_IN_BLOCK); // Fully occupied blocks
		int partially_occupied = fsize % MAX_DATA_IN_BLOCK;
		if ( partially_occupied > 0) // Partially occupied block
		{
			file_curr_blocks++;
		}
		// How much more data do we have in the final block?
		int block_remainder = MAX_DATA_IN_BLOCK - partially_occupied;
		
		// Do we need to append?
		int append_data_size = 0;
		if(fsize-offset+size > 0)
		{
			append_data_size = fsize-offset+size;
		}
		
		// !-- ALL FAT TABLE [subscripts] MUST BE -1 (off by one) --!
		// Load entire fat table for FAT traversals
		short fat_table[FAT_ENTRIES_PER_BLOCK * FAT_TABLE_BLOCK_SIZE];
		load_fat(&fat_table);
		
		// If our append will fit into the unfilled block
		if(append_data_size > 0 && (append_data_size - block_remainder) < 1)
		{
			#ifdef CS1550_DEBUG
				printf("[write] : Append will fit into last block\n");
			#endif
		}
		// Otherwise, if our append will spill over into new blocks...
		else if(append_data_size > 0)
		{
			#ifdef CS1550_DEBUG
				printf("[write] : Append will not fit into last block - must append blocks to file\n");
			#endif
			// Allocate some new blocks to the FAT
			
			// Determine how many blocks we need
			int overflowing_bytes = append_data_size - block_remainder;
			int blocks_needed = overflowing_bytes / MAX_DATA_IN_BLOCK;
			
			// Follow FAT to end and allocate new blocks
			#ifdef CS1550_DEBUG
				printf("[write] : Following FAT file until EOF...\n");
			#endif
			int curr_fat_index = fstart_block;
			while(fat_table[fstart_block-1] != EOF) // While not at end of file
			{
				#ifdef CS1550_DEBUG
					printf("[write] : curr_fat_index from %d (%d) ", curr_fat_index, curr_fat_index-1);
				#endif
				curr_fat_index = fat_table[curr_fat_index-1]; // Grab next entry
				#ifdef CS1550_DEBUG
					printf("to %d (%d)\n", curr_fat_index, curr_fat_index-1);
				#endif
			}
			#ifdef CS1550_DEBUG
				printf("[write] : EOF detected at FAT entry %d (%d)\n", curr_fat_index, curr_fat_index-1);
			#endif
			
			while(blocks_needed > 0)
			{
				fat_table[curr_fat_index] = find_next_empty_fat_block();
				#ifdef CS1550_DEBUG
					printf("[write] : New FAT entry: %d\n", fat_table[curr_fat_index]);
				#endif
				curr_fat_index = fat_table[curr_fat_index-1];
				blocks_needed--;
			}
			
		}
	#ifdef CS1550_DEBUG
		else { printf("[write] : There is no appending to the file\n"); }
	#endif
		
		// write data
		if(!file_curr_blocks && size <= 512) // No data in block and < 512B?
		{
			cs1550_disk_block db;
			int i = 0;
			for(i = 0; i < size; i++)
			{
				db.data[i] = buf[i];
			}
			write_file_block(&db, fstart_block);
		}
		//set size (should be same as input) and return, or error
		
		// Fix size in file directory
		fsize = size; // Pretty sure this is correct
		file_update_size(&dir, filename, extension, fsize);
		write_to_block(&dir, subdir_at);
	}
	return size;
}

/******************************************************************************
 *
 *  DO NOT MODIFY ANYTHING BELOW THIS LINE
 *                                                        k
 *****************************************************************************/

/*
 * truncate is called when a new file is created (with a 0 size) or when an
 * existing file is made shorter. We're not handling deleting files or 
 * truncating existing ones, so all we need to do here is to initialize
 * the appropriate directory entry.
 *
 */
static int cs1550_truncate(const char *path, off_t size)
{
	(void) path;
	(void) size;

    return 0;
}


/* 
 * Called when we open a file
 *
 */
static int cs1550_open(const char *path, struct fuse_file_info *fi)
{
	(void) path;
	(void) fi;
    /*
        //if we can't find the desired file, return an error
        return -ENOENT;
    */

    //It's not really necessary for this project to anything in open

    /* We're not going to worry about permissions for this project, but 
	   if we were and we don't have them to the file we should return an error

        return -EACCES;
    */

    return 0; //success!
}

/*
 * Called when close is called on a file descriptor, but because it might
 * have been dup'ed, this isn't a guarantee we won't ever need the file 
 * again. For us, return success simply to avoid the unimplemented error
 * in the CS1550_DEBUG log.
 */
static int cs1550_flush (const char *path , struct fuse_file_info *fi)
{
	(void) path;
	(void) fi;

	return 0; //success!
}


//register our new functions as the implementations of the syscalls
static struct fuse_operations hello_oper = {
    .getattr	= cs1550_getattr,
    .readdir	= cs1550_readdir,
    .mkdir	= cs1550_mkdir,
	.rmdir = cs1550_rmdir,
    .read	= cs1550_read,
    .write	= cs1550_write,
	.mknod	= cs1550_mknod,
	.unlink = cs1550_unlink,
	.truncate = cs1550_truncate,
	.flush = cs1550_flush,
	.open	= cs1550_open,
};

//Don't change this.
int main(int argc, char *argv[])
{
	return fuse_main(argc, argv, &hello_oper, NULL);
}
