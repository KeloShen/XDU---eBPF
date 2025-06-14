# XDU---eBPF
XDU软件工程云计算课程大作业-eBPF捕获系统调用

## 一、项目简介

本项目旨在通过eBPF技术，监控容器环境下进程的系统调用，并将系统调用与容器ID进行关联。学习如何在Linux内核中利用eBPF进行可观测性开发，体验云原生基础设施的底层实现。

## 二、目录结构说明

- `eBPF相关大作业/`  
  包含作业题目说明、示例代码（C语言）、以及相关文档。
- `ebpf_systemcall_monitor/`  
  主要实现目录，包含基于Python+BCC的eBPF系统调用监控程序、依赖说明、实验过程记录等。
- `Learning eBPF New Version.pdf`、`What is eBPF New Version.pdf`  
  eBPF学习资料，建议先阅读。

## 三、作业完成建议

1. **环境准备**
   - 推荐使用较新版本的Linux（如Ubuntu 22.04/24.04），并确保内核版本较高（5.x及以上）。
   - 安装Docker，便于实验容器环境。
   - 安装eBPF开发相关依赖（如BCC、libbpf、cilium/ebpf等，建议优先用BCC，Python友好）。

2. **理解eBPF与容器监控**
   - 阅读`eBPF相关大作业/使用eBPF捕获容器系统调用情况.docx`，明确作业目标。
   - 参考`sample_syscall.c`和`sample_fileopen.c`，理解eBPF程序的基本结构。
   - 阅读`ebpf_systemcall_monitor/ebpf_syscall_monitor.py`，了解如何用Python+BCC实现系统调用监控。

3. **动手实践**
   - 按照`Requirement.txt`和`[实验过程记录]eBPF容器系统调用监控.md`的步骤，配置环境并运行监控程序。
   - 使用`docker run -it --rm ubuntu`等命令启动容器，在容器内执行常见命令，观察监控结果。
   - 可以尝试修改eBPF程序，采集更多信息或优化输出格式。

4. **实验记录与总结**
   - 记录遇到的问题及解决方法，形成自己的实验报告。
   - 思考eBPF在云计算与大数据场景下的实际应用价值。

## 四、与本方向（云计算与大数据）的关系

- **云计算**：eBPF是云原生基础设施（如Kubernetes、Service Mesh、云安全等）中的核心技术之一。它能实现高效、低开销的内核级监控与网络流量分析，是现代云平台可观测性、故障排查和安全防护的关键工具。
- **大数据**：在大规模分布式系统中，eBPF可用于采集系统运行时的详细数据（如系统调用、网络包、性能指标等），为大数据分析平台提供实时、精准的原始数据支撑，助力智能运维与安全分析。

## 五、参考资料

- [eBPF官方文档](https://ebpf.io/)
- [BCC项目文档](https://github.com/iovisor/bcc)
- [Cilium eBPF教程](https://cilium.io/)
- 项目内PDF学习资料
