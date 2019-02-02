# -*- coding: utf-8  -*-
# 执行命令格式：python filter_pcap.py [ip] [12位通话开始时间(YYYYmmddhh24M)] [持续时间min]
import configparser
import os
import time
import sys
import datetime
import logging
from subprocess import Popen
import queue
import multiprocessing
from multiprocessing.managers import BaseManager


class QueueManager(BaseManager):
    pass


task_queue = queue.Queue()

ip_arvg = sys.argv[1]
dt_Begin_argv = sys.argv[2]
dur_min = sys.argv[3]  # 从通话开始抓取持续n分钟报文

srcpath = os.path.dirname(os.path.realpath(__file__))
conf = configparser.ConfigParser()
confile = os.path.join(srcpath, 'conf.ini')
conf.read(confile)

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)

pacp_bak_dir = conf.get('source', 'pacp_bak_dir')
merge_dir = conf.get('target', 'merge_dir')
source_dir = pacp_bak_dir + dt_Begin_argv[:8]  # 搜索目标文件夹
target_dir = merge_dir + dt_Begin_argv[:8]  # merge存放文件夹
tshark_exe = conf.get('exefile', 'tshark_exe')
mergecap_exe = conf.get('exefile', 'mergecap_exe')


def gen_scan_file_list(begin_time):
    dur_time_list = []
    time_min_str = begin_time
    for i in range(int(dur_min)):
        if time_min_str[-2:] != "59":
            dur_time_list.append(time_min_str)
            time_min_str_int = int(time_min_str[-2:]) + 1
            time_min_str = time_min_str[:10] + str(time_min_str_int).zfill(2)  # 个位数前面补一个"0"
        elif time_min_str[-2:] == "59":
            dur_time_list.append(time_min_str)
            time_min_str_min = "00"
            time_hour_str_int = int(time_min_str[8:10]) + 1
            time_min_str = time_min_str[:8] + str(time_hour_str_int) + time_min_str_min
    return dur_time_list


def gen_source_file():
    for f in os.listdir(source_dir):
        if f[-19:-7] in gen_scan_file_list(dt_Begin_argv):
            f = os.path.join(source_dir, f)
            task_queue.put(f)
            print("{0} has put in the queue".format(f))
    return task_queue.qsize()


def gen_abs_file(file_name):
    return os.path.join(source_dir, file_name)


def work_process(abs_file, dir_path):
    """
    :param 文件绝对路径 abs_file:
    :param 生成文件的目录 dir_path:
    """
    file_name = os.path.basename(abs_file)
    dst_file = file_name[8:13] + ".pcap"  # 过滤后生成的文件名
    isexists = os.path.exists(dir_path)
    if not isexists:
        os.makedirs(dir_path)
    pcap_file = os.path.join(dir_path, dst_file)
    cmd = (r'{0} -r {1} -R ip.addr=={2} -2 -w {3}'.format(tshark_exe, abs_file, ip_arvg, pcap_file))
    print(cmd)
    a = Popen(cmd, shell=True)
    a.wait()


def merge_process(dir_path):
    """
    :param 生成文件的目录 dir_path:
    """
    merged_file = os.path.join(dir_path, 'mergecap.pcap')
    pcap_files = os.path.join(dir_path, '*.pcap')
    cmd = (r'{0} -w {1} {2}'.format(mergecap_exe, merged_file, pcap_files))
    logger.info("Merging......")
    b = Popen(cmd, shell=True)
    b.wait()
    logger.info("Generated in {0}".format(dir_path))
    return


if __name__ == "__main__":
    dt = datetime.datetime.now()
    file_tag = dt.strftime("%M%S")
    dst_dir = ip_arvg.strip('.') + "_" + dt_Begin_argv[8:12] + "_" + str(dur_min) + "_" + file_tag
    dst_dir_path = os.path.join(target_dir, dst_dir)
    file_count = gen_source_file()

    if file_count > 0:
        logger.info("Analysing......")
        pool = multiprocessing.Pool(processes=2)
        for j in range(task_queue.qsize()):
            file = task_queue.get()
            print("{0} has got from the queue".format(file))
            pool.apply_async(work_process, (file, dst_dir_path))  # 维持执行的进程总数为processes，当一个进程执行完毕后会添加新的进程进去
            time.sleep(0.5)  # 调用tshark
        pool.close()
        pool.join()   # 调用join之前，先调用close函数，否则会出错。执行完close后不会有新的进程加入到pool,join函数等待所有子进程结束
        merge_process(dst_dir_path)
    else:
        print("No files Found or parameter is Wrong")