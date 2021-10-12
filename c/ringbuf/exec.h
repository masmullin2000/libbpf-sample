#ifndef __EXEC_H__
#define __EXEC_H__

struct exec_evt {
    pid_t pid;
    pid_t tgid;
    char comm[32];
    char file[32];
};

#endif // __EXEC_H__
