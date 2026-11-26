# 中兴ax3000开启telnet工具（备份）
# 我不是原作者，我不是原作者，我不是原作者
### linux用户、macos用户可以尝试通过workbuddy、codex等agent协助处理，


### windows用户直接从介绍里的连接下载，依靠原始作者的方案


### 支持e2633（原作者适配目标）、e2631（自己测出来的），其余设备查看原始帖子评论其余网友的测试

需要：node环境，（我个人使用的是Node.js v24.22.3）

教程：
     
     中兴路由-系统-备份配置-备份用户配置-备份配置，下载的文件保存为config.bin，放到telnet_enable.js同目录，

     然后运行`点击开启telnet.bat`（非windows用户尝试通过agent使用，有能力的自行运行），运行完成后会生成`config-telnet-enable.bin`，
     
     然后回到  中兴路由-系统-备份配置-恢复用户配置-点击输入框-选择生成的`config-telnet-enable.bin`-恢复配置， 
     
     设备重启后，除了telnet配置发生变化，其余不变，`telnet <中兴路由ip>`，用户名密码都是admin

