/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>
  Copyright (C) 2011       Sebastian Pipping <sebastian@pipping.org>

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.

  gcc -Wall fusexmp.c `pkg-config fuse --cflags --libs` -o fusexmp
*/

#define FUSE_USE_VERSION 26

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef linux
/* For pread()/pwrite()/utimensat() */
#define _XOPEN_SOURCE 700
#endif

#include <fuse.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/syslog.h>
#include "aes.h"

#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#endif

//	constant definitions
#define AES128_KEY_LEN		16	// in bytes
#define AES128_BLOCK_SIZE	16	// in bytes

//	useful macros
#define ctrace()		{printf("[%u]", __LINE__);}
#define getNibble(x)	(isdigit(x) ? x-'0': toupper(x)-'A'+10)

union _CryptData {
	char bytes[16];
	struct {
		unsigned long i_number;
		unsigned long counter;	
	} cd;
};

typedef union _CryptData CryptData;


char *xorBuffers( char *dest, char *bufA, char *bufB, unsigned length);
int cryptFile(char *fileName, char *inputKey);

static int xmp_getattr(const char *path, struct stat *stbuf)
{
	int res;

	res = lstat(path, stbuf);  
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_access(const char *path, int mask)
{
	int res;

	res = access(path, mask);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_readlink(const char *path, char *buf, size_t size)
{
	int res;

	res = readlink(path, buf, size - 1);
	if (res == -1)
		return -errno;

	buf[res] = '\0';
	return 0;
}


static int xmp_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
		       off_t offset, struct fuse_file_info *fi)
{
	DIR *dp;
	struct dirent *de;

	(void) offset;
	(void) fi;

	dp = opendir(path);
	if (dp == NULL)
		return -errno;

	while ((de = readdir(dp)) != NULL) {
		struct stat st;
		memset(&st, 0, sizeof(st));
		st.st_ino = de->d_ino;
		st.st_mode = de->d_type << 12;
		if (filler(buf, de->d_name, &st, 0))
			break;
	}

	closedir(dp);
	return 0;
}

static int xmp_mknod(const char *path, mode_t mode, dev_t rdev)
{
	int res;

	/* On Linux this could just be 'mknod(path, mode, rdev)' but this
	   is more portable */
	if (S_ISREG(mode)) {
		res = open(path, O_CREAT | O_EXCL | O_WRONLY, mode);
		if (res >= 0)
			res = close(res);
	} else if (S_ISFIFO(mode))
		res = mkfifo(path, mode);
	else
		res = mknod(path, mode, rdev);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_mkdir(const char *path, mode_t mode)
{
	int res;

	res = mkdir(path, mode);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_unlink(const char *path)
{
	int res;

	res = unlink(path);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_rmdir(const char *path)
{
	int res;

	res = rmdir(path);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_symlink(const char *from, const char *to)
{
	int res;

	res = symlink(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_rename(const char *from, const char *to)
{
	int res;

	res = rename(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_link(const char *from, const char *to)
{
	int res;

	res = link(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_chmod(const char *path, mode_t mode)
{
	int res;
	res = chmod(path, mode);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_chown(const char *path, uid_t uid, gid_t gid)
{
	int res;

	res = lchown(path, uid, gid);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_truncate(const char *path, off_t size)
{
	int res;

	res = truncate(path, size);
	if (res == -1)
		return -errno;

	return 0;
}

#ifdef HAVE_UTIMENSAT
static int xmp_utimens(const char *path, const struct timespec ts[2])
{
	int res;

	/* don't use utime/utimes since they follow symlinks */
	res = utimensat(0, path, ts, AT_SYMLINK_NOFOLLOW);
	if (res == -1)
		return -errno;

	return 0;
}
#endif

static int xmp_open(const char *path, struct fuse_file_info *fi)
{
	int res;

	res = open(path, fi->flags);
	if (res == -1)
		return -errno;

	close(res);
	return 0;
}

static int xmp_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
	int fd;
	int res;

	(void) fi;
     struct fuse_context *context;
	context = fuse_get_context();
	fd = open(path, O_RDONLY);
	if (fd == -1)
		return -errno;


	struct stat sb;
	if (0 != fstat(fd, &sb))
	{
		printf("file access error %d\n", errno);
		res = errno;
		close(fd);
		return res;
	}
    if(sb.st_mode & S_ISVTX)
    {
        unsigned int k0 = 0;
        syscall(565, context->uid, 0, &k0);
        unsigned int k1 = 0;
        syscall(565, context->uid, 1, &k1);
        if(k0 == 0 && k1 == 0) // user doesn't have the key set
		{
			res = pread(fd, buf, size, offset);
		}
        else
        {
            char first_half[AES128_KEY_LEN];
            char second_half[AES128_KEY_LEN];
            char inputKey[17];

            sprintf(first_half, "%x", k0);
            sprintf(second_half, "%x", k1);
            strcpy(inputKey, first_half);
            strcat(inputKey, second_half);
            inputKey[16] = '\0';

			char fileName[FILENAME_MAX];
			strcpy(fileName, path);
			res = cryptFile(fileName, inputKey);
			res = pread(fd, buf, size, offset);
			cryptFile(fileName, inputKey);
		}
    }
    else
    {
        res = pread(fd, buf, size, offset);
        if (res == -1)
		    res = -errno;
    }
	close(fd);
	return res;
}

int cryptFile(char *fileName, char *inputKey)
{
	int fd=-1;
	int status = 0;
	off_t offset = 0;
	CryptData cd;
	char readBuffer[AES128_BLOCK_SIZE];
	char writeBuffer[AES128_BLOCK_SIZE];
	char cdEncrypted[AES128_BLOCK_SIZE];
	char iv[AES128_BLOCK_SIZE];
	size_t sizeRead = 0;
	size_t wroteSize = 0;
	bool firstPass = true;

	do
	{
		//	open file read+write mode with exclusive access
		fd = open(fileName, O_RDWR | O_EXCL);
		if (-1 == fd)
		{
			printf("file open error %d\n", errno);
			status = errno;
			break;
		}
		struct stat sb;
		if (0 != fstat(fd, &sb))
		{
			printf("file access error %d\n", errno);
			status = errno;
			close(fd);
			break;
		}
		do
		{
			sizeRead = read(fd, readBuffer, AES128_BLOCK_SIZE);
			if (-1 == sizeRead)
			{
				printf("file read error %d\n", errno);
				status = errno;
				break;
			}
			if (0 == sizeRead)
			{
				//	reached end of file
				break;
			}
			memset(&cd, 0, sizeof(cd));
			cd.cd.i_number = sb.st_ino;
			cd.cd.counter =  offset / AES128_BLOCK_SIZE; 

			if (0 == offset) // initialize init vector
				memset(&iv, 0, sizeof(iv));
			AES128_CBC_encrypt_buffer((uint8_t *)cdEncrypted, 
					(uint8_t *)cd.bytes, AES128_BLOCK_SIZE, 
					(uint8_t *)inputKey, (uint8_t *)iv);

			memcpy(iv, cdEncrypted, AES128_BLOCK_SIZE);

			//	seek back to where the data was read from
			if (offset != lseek(fd, offset, SEEK_SET))
			{
				printf("file seek error %d\n", errno);
				status = errno;
				break;
			}

			xorBuffers(writeBuffer, cdEncrypted, readBuffer, AES128_BLOCK_SIZE);
			wroteSize = write(fd, writeBuffer, sizeRead);
			if (sizeRead != wroteSize)
			{
				printf("file write error %d\n", errno);
				status = errno;
				break;
			}
			offset += AES128_BLOCK_SIZE;
		} while (true);
		close(fd);

	} while (false);

	return status;
}


//
//	XOR corresponding bytes in two buffers to destination
//	
char *xorBuffers(char *destination, char *bufA, char *bufB, unsigned length)
{
	for (unsigned u=0; u<length;u++)
		destination[u] = bufA[u] ^ bufB[u];
	return destination;
}

static int xmp_create(const char *path, mode_t mode, struct fuse_file_info *fi)
{
    int res;

	res = creat(path, mode);
	if (res == -1)
		return -errno;

	return 0;
}


static int xmp_write(const char *path, const char *buf, size_t size,
		     off_t offset, struct fuse_file_info *fi)
{
	int fd;
	int res;

	(void) fi;
	struct fuse_context *context;
	context = fuse_get_context();
	fd = open(path, O_WRONLY);
	if (fd == -1)
		return -errno;

	struct stat sb;
	if (0 != fstat(fd, &sb))
	{
		printf("file access error %d\n", errno);
		res = errno;
		close(fd);
		return res;
	}
    if(sb.st_mode & S_ISVTX)
    {
		res = pwrite(fd, buf, size, offset);

		unsigned int k0 = 0;
        syscall(565, context->uid, 0, &k0);
        unsigned int k1 = 0;
        syscall(565, context->uid, 1, &k1);

		char first_half[AES128_KEY_LEN];
		char second_half[AES128_KEY_LEN];
		char inputKey[17];

		sprintf(first_half, "%x", k0);
		sprintf(second_half, "%x", k1);
		strcpy(inputKey, first_half);
		strcat(inputKey, second_half);
		inputKey[16] = '\0';

		char fileName[FILENAME_MAX];
		strcpy(fileName, path);
		cryptFile(fileName, inputKey);	
	}
	else
	{
		res = pwrite(fd, buf, size, offset);
	}
	
	if (res == -1)
		res = -errno;

	close(fd);
	return res;
}

static int xmp_statfs(const char *path, struct statvfs *stbuf)
{
	int res;

	res = statvfs(path, stbuf);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_release(const char *path, struct fuse_file_info *fi)
{
	/* Just a stub.	 This method is optional and can safely be left
	   unimplemented */

	(void) path;
	(void) fi;
	return 0;
}

static int xmp_fsync(const char *path, int isdatasync,
		     struct fuse_file_info *fi)
{
	/* Just a stub.	 This method is optional and can safely be left
	   unimplemented */

	(void) path;
	(void) isdatasync;
	(void) fi;
	return 0;
}

#ifdef HAVE_POSIX_FALLOCATE
static int xmp_fallocate(const char *path, int mode,
			off_t offset, off_t length, struct fuse_file_info *fi)
{
	int fd;
	int res;

	(void) fi;

	if (mode)
		return -EOPNOTSUPP;

	fd = open(path, O_WRONLY);
	if (fd == -1)
		return -errno;

	res = -posix_fallocate(fd, offset, length);

	close(fd);
	return res;
}
#endif

#ifdef HAVE_SETXATTR
/* xattr operations are optional and can safely be left unimplemented */
static int xmp_setxattr(const char *path, const char *name, const char *value,
			size_t size, int flags)
{
	int res = lsetxattr(path, name, value, size, flags);
	if (res == -1)
		return -errno;
	return 0;
}

static int xmp_getxattr(const char *path, const char *name, char *value,
			size_t size)
{
	int res = lgetxattr(path, name, value, size);
	if (res == -1)
		return -errno;
	return res;
}

static int xmp_listxattr(const char *path, char *list, size_t size)
{
	int res = llistxattr(path, list, size);
	if (res == -1)
		return -errno;
	return res;
}

static int xmp_removexattr(const char *path, const char *name)
{
	int res = lremovexattr(path, name);
	if (res == -1)
		return -errno;
	return 0;
}
#endif /* HAVE_SETXATTR */

static struct fuse_operations xmp_oper = {
	.getattr	= xmp_getattr,
	.access		= xmp_access,
	.readlink	= xmp_readlink,
	.readdir	= xmp_readdir,
	.mknod		= xmp_mknod,
	.mkdir		= xmp_mkdir,
	.symlink	= xmp_symlink,
	.unlink		= xmp_unlink,
	.rmdir		= xmp_rmdir,
	.rename		= xmp_rename,
	.link		= xmp_link,
	.chmod		= xmp_chmod,
	.chown		= xmp_chown,
	.truncate	= xmp_truncate,
#ifdef HAVE_UTIMENSAT
	.utimens	= xmp_utimens,
#endif
	.open		= xmp_open,
	.read		= xmp_read,
    .create     = xmp_create,
	.write		= xmp_write,
	.statfs		= xmp_statfs,
	.release	= xmp_release,
	.fsync		= xmp_fsync,
#ifdef HAVE_POSIX_FALLOCATE
	.fallocate	= xmp_fallocate,
#endif
#ifdef HAVE_SETXATTR
	.setxattr	= xmp_setxattr,
	.getxattr	= xmp_getxattr,
	.listxattr	= xmp_listxattr,
	.removexattr	= xmp_removexattr,
#endif
};

int main(int argc, char *argv[])
{
	umask(0);
	return fuse_main(argc, argv, &xmp_oper, NULL);
}