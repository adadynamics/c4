
#include <poll.h>
#include <sys/syscall.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/statfs.h>
#include <sys/statvfs.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <sys/select.h>
#include <sys/file.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/io.h>
#include <sys/xattr.h>
#include <linux/ioprio.h>
#include <sys/inotify.h>
#include <sys/quota.h>
#include <sys/times.h>
#include <pthread.h>

#ifdef ADL_XFS_XQM_H
#include <xfs/xqm.h>
#endif

#include  <linux/dqblk_xfs.h>
#include <linux/aio_abi.h>
#include <sys/epoll.h>

#include <sys/time.h>
#include <utime.h>
#include <sys/fanotify.h>
#include <linux/close_range.h>
#include <linux/mount.h>
#include <time.h>
#include <sys/timerfd.h>
#include <sys/wait.h>
#include <sys/timex.h>
#include <sys/shm.h>
#include <sys/msg.h>
#include <mqueue.h>
#include <signal.h>
#include <linux/futex.h>
#include <sys/sendfile.h>
#include <linux/openat2.h>
#include <sys/syscall.h>
#include <dirent.h>
#include <sys/sem.h>
#include <linux/capability.h>
#include <linux/sched.h>
#include <linux/sched/types.h>
#include <sched.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <asm/ldt.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <linux/version.h>
#include <sys/ptrace.h>
#include <linux/bpf.h> 
#include <grp.h>
#include <crypt.h>
#include <pwd.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/eventfd.h>
#include <sys/signalfd.h>
#include <linux/reboot.h>
#include <linux/module.h>
#include <linux/kexec.h>
#include <sys/klog.h>
#include <sys/sysinfo.h>
#include <sys/random.h>
#include <numaif.h>
//#include <linux/keyctl.h>
#include <linux/membarrier.h>
#include <keyutils.h>
#include <linux/userfaultfd.h>
#include <sys/swap.h>
#include <sys/mman.h>
#include <shadow.h>



int openat2(int dirfd,const char *pathname,struct open_how *how,size_t size)
{
    return syscall(SYS_openat2,dirfd,pathname,how,size);  
}


int faccessat2(int dirfd,const char *path,int mode,int flags)
{
    return syscall(SYS_faccessat2,dirfd,path,mode,flags);
}


int pivot_root(const char *new_root, const char *put_old)
{
    return syscall(SYS_pivot_root,new_root,put_old);
}


int io_setup(unsigned int nr_events,aio_context_t *ctx_id)
{
    return syscall(SYS_io_setup,nr_events,ctx_id);
}


int io_destroy(aio_context_t ctx_id)
{
    return syscall(SYS_io_destroy,ctx_id);
}


int io_getevents(aio_context_t ctx_id,long min_nr, long nr, struct io_event *events,struct timespec *timeout)
{
    return syscall(SYS_io_getevents,ctx_id,min_nr,nr,events,timeout);
}


int io_submit(aio_context_t ctx_id, long nr, struct iocb **iocb)
{
    return syscall(SYS_io_submit,ctx_id,nr,iocb);
}


int io_cancel(aio_context_t ctx_id, struct iocb *iocb,struct io_event *result)
{
    return syscall(SYS_io_cancel,ctx_id,iocb,result);
}


int lookup_dcookie(uint64_t cookie, char *buffer,size_t len)
{
    return syscall(SYS_lookup_dcookie,cookie,buffer,len);
}


int ioprio_set(int which,int who,int ioprio)
{
    return syscall(SYS_ioprio_set,which,who,ioprio);
}


int ioprio_get(int which,int who)
{
    return syscall(SYS_ioprio_get,which,who);
}


int mq_getsetattr(mqd_t mqdes,const struct mq_attr *newattr, struct mq_attr *oldattr)
{
    return syscall(SYS_mq_getsetattr, mqdes,newattr,oldattr);
}


int futex(uint32_t *uaddr, int futex_op, uint32_t val,const struct timespec *timeout,uint32_t *uaddr2, uint32_t val3)
{
    return syscall(SYS_futex,uaddr,futex_op,val,timeout,uaddr2,val3);
}


int get_robust_list(int pid,struct robust_list_head **head_ptr, size_t *len_ptr)
{
    return syscall(SYS_get_robust_list,pid,head_ptr,len_ptr);
}


int set_robust_list(struct robust_list_head *head,size_t len)
{
    return syscall(SYS_set_robust_list,head,len);
}


int capget(cap_user_header_t hdrp,cap_user_data_t datap)
{
    return syscall(SYS_capget,hdrp,datap);
}


int capset(cap_user_header_t hdrp,const cap_user_data_t datap)
{
    return syscall(SYS_capset,hdrp,datap);
}


long clone3(struct clone_args *cl_args, size_t size)
{
    return syscall(SYS_clone3,cl_args,size);
}


void exit_group(int status)
{
    syscall(SYS_exit_group,status);
}


int get_thread_area(struct user_desc *u_info)
{
    return syscall(SYS_get_thread_area,u_info);
}


int pidfd_getfd(int pidfd, int targetfd,unsigned int flags)
{
    return syscall(SYS_pidfd_getfd,pidfd,targetfd,flags);
}


int pidfd_open(pid_t pid,unsigned int flags)
{
    return syscall(SYS_pidfd_open,pid,flags);
}


int sched_getattr(pid_t pid,struct sched_attr *attr,unsigned int size,unsigned int flags)
{
    return syscall(SYS_sched_getattr,pid,attr,size,flags);
}


int sched_setattr(pid_t pid, struct sched_attr *attr,unsigned int flags)
{
    return syscall(SYS_sched_setattr,pid,attr,flags);
}

int set_thread_area(struct user_desc *u_info)
{
    return syscall(SYS_set_thread_area,u_info);
}


int set_tid_address(int *tidptr)
{
    return syscall(SYS_set_tid_address,tidptr);
}


int modify_ldt(int func, void *ptr,unsigned long bytecount)
{
    return syscall(SYS_modify_ldt,func,ptr,bytecount);
}


int seccomp(unsigned int operation,unsigned int flags,void *args)
{
    return syscall(SYS_seccomp,operation,flags,args);
}


int kcmp(pid_t pid1, pid_t pid2, int type,unsigned long idx1, unsigned long idx2)
{
    return syscall(SYS_kcmp,pid1,pid2,type,idx1,idx2);
}


int bpf(int cmd, union bpf_attr *attr, unsigned int size)
{
    return syscall(SYS_bpf,cmd,attr,size);
}


int pidfd_send_signal(int pidfd, int sig,siginfo_t *info, unsigned int flags)
{
    return syscall(SYS_pidfd_send_signal,pidfd,sig,info,flags);
}


int reboot(int magic,int magic2,int op,void *arg)
{
    return syscall(SYS_reboot,magic,magic2,op,arg);
}


int delete_module(const char *name,unsigned int flags)
{
    return syscall(SYS_delete_module,name,flags);
}


int init_module(void * module_image,unsigned long len,const char *param_values)
{
    return syscall(SYS_init_module,module_image,len,param_values);
}


int finit_module(int fd,const char *param_values,int flags)
{
    return syscall(SYS_finit_module,fd,param_values,flags);
}


int kexec_file_load(int kernel_fd, int initrd_fd,unsigned long cmdline_len, const char *cmdline,unsigned long flags)
{
    return syscall(SYS_kexec_file_load,kernel_fd,initrd_fd,cmdline_len,cmdline,flags);
}


int kexec_load(unsigned long entry,unsigned long nr_segments,struct kexec_segment *segments,unsigned long flags)
{
    return syscall(SYS_kexec_load,entry,nr_segments,segments,flags);
}


int syslog(int type,char *bufp,int len)
{
    return syscall(SYS_syslog,type,bufp,len);
}


/*
int keyctl(int operation,unsigned long arg2,unsigned long arg3,unsigned long arg4,unsigned long arg5)
{
    return syscall(SYS_keyctl,operation,arg2,arg3,arg4,arg5);
}
*/



int membarrier(int cmd,unsigned int flags,int cpu_id)
{
    return syscall(SYS_membarrier,cmd,flags,cpu_id);
}


int memfd_secret(unsigned int flags)
{
    return syscall(SYS_memfd_secret,flags);
}


int userfaultfd(int flags)
{
    return syscall(SYS_userfaultfd,flags);
}



