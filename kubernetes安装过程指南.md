# **Kubernetes软件安装指南**



# 环境准备
## 安装docker软件
```
yum install docker
systemctl start docker
systemctl status docker
```

## 配置docker镜像仓库
```
cat >/etc/docker/daemon.json <<EOF
{
"insecure-registries" : ["rnd-dockerhub.huawei.com"],
"exec-opts": ["native.cgroupdriver=systemd"]
}
EOF

systemctl restart docker
```
重启docker服务后，可以使用`docker info`查看`Cgroup Driver: `字段是否变更为`systemd`

## 安装kubeadm/kubectl/kubelet软件
```yum install kubeadm kubectl kubelet```

## 下载kubernetes管理面容器镜像

因为外部网络不通，通过kubeadm自动下载镜像会安装失败。需要准备离线镜像，通过本地导入的方式准备镜像。

### 通过kubeadm查看需要哪些容器镜像
通过`kubeadm config images list`查看需要下载哪些镜像

```
k8s.gcr.io/kube-apiserver:v1.23.1
k8s.gcr.io/kube-controller-manager:v1.23.1
k8s.gcr.io/kube-scheduler:v1.23.1
k8s.gcr.io/kube-proxy:v1.23.1
k8s.gcr.io/pause:3.6
k8s.gcr.io/etcd:3.5.1-0
k8s.gcr.io/coredns/coredns:v1.8.6
calica.yaml
```

可以通过--kubernetes-version参数指定版本，```kubeadm config images list --kubernetes-version=v1.13.2```。

kubeadm命令与容器镜像版本有配套关系，有支持的最低版本约束。

### 下载管理面容器镜像

离线tar包下载地址：
下载kube-proxy/kube-apiserver/kube-scheduler/kube-config-manager
https://www.downloadkubernetes.com/

https://dl.k8s.io/v1.13.2/bin/linux/amd64/kube-apiserver.tar

注：pause/etcd/coredns镜像需要另外下载。

### 下载flannel容器镜像
```
quay.io/coreos/flannel:v0.13.1-rc1
```

### 本地导入离线镜像
```
docker load -i ./kube-apiserver.tar
docker load -i ./kube-scheduler.tar
docker load -i ./kube-controller-manager.tar
docker load -i ./kube-proxy.tar
docker load -i ./k8s.gcr.io_pause-3.2.tar
docker load -i ./k8s.gcr.io-etcd-3.4.3-0.tar
docker load -i ./k8s.gcr.io_coredns-1.6.7.tar
docker load -i ./flannel.tar
```

## 环境配置

* 查看主机名解析是否正常
执行```hostname -i```命令能够返回大网地址，返回IP就是后续安装kube-apiserver要侦听的地址

```ping $(hostname)```能够ping通大王地址

```ping localhost```能ping通127.0.0.1

查看`/etc/hosts`文件中配置是否正确。


* 关闭swap
```
swapoff -a
sed -ri 's/.*swap.*/#&/' /etc/fstab
```

* 关闭SELinux
```
setenforce 0
sed -i 's/enforcing/disabled/' /etc/selinux/config
```

* 关闭防火墙
```
systemctl stop firewalld
systemctl disable firewalld
```

* 配置内核iptables参数
/etc/sysctl.conf文件中增加
```
net.bridge.bridge-nf-call-iptables = 1
```
执行`sysctl -p`刷新内核参数



* 配置docker服务的cri.nativedriver从cgroupfs为systemd

配置指导：
原因参考：[[1]][容器运行时]



# 软件安装

## Master节点安装

### 初始化kubernetes master节点

```SHELL
#获取机器IP
IPA=`ip addr | grep -w -A2 'eth0:'| grep inet | awk '2 {print $2}' | sed "s#/.*##"`
#初始化k8s init
kubeadm init --apiserver-advertise-address=$IPA --kubernetes-version v1.23.1 \
--service-cidr=10.96.0.0/12 --pod-network-cidr=10.244.0.0/16
#创建目录
mkdir -p $HOME/.kube
sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
sudo chown $(id -u):$(id -g) $HOME/.kube/config
```

说明：
--apiserver-advertise-address: kube-apiserver的侦听地址
--kubernetes-version：配套kubernetes镜像的版本号
--service-cidr：服务预留网段
--pod-network-cidr：POD内网预留地址段

### 查看安装结果
执行命令：

```kubectl get node```查看节点状态

```kubectl get componentstatus```查看组件状态

```kubectl get namespace```or```kubectl get ns``` 查看namespace


### 解决master节点状态为NotReady的问题

#### 问题现象
通过`kubectl get node`查看节点状态，master节点为NotReady
```
NAME              STATUS   ROLES    AGE   VERSION
dggphicprd09484   NotReady    master   19h   v1.18.0
```

通过`kubectl describe nodes dggphicprd09484`查看节点状态，错误信息为：
```
runtime network not ready: NetworkReady=false reason:NetworkPluginNotReady message:docker: network plugin is not ready: cni config uninitialized
```
![图片说明](http://image.huawei.com/tiny-lts/v1/images/c421ea6d7f1b8b75bdef7f7c8c358503_1498x150.png@900-0-90-f.png)


通过`systemctl status kubelet`或`journalctl -u kubelet -ef`查看kubelet服务的报错日志：
```
Unable to update cni config: No networks found in /etc/cni/net.d
```
![图片说明](http://image.huawei.com/tiny-lts/v1/images/46710f190582475c5e484bbb72a2f802_1498x332.png@900-0-90-f.png)

#### 解决方法

步骤1. 生成flannal配置文件，保存为flannal.yaml

```YAML
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: psp.flannel.unprivileged
  annotations:
    seccomp.security.alpha.kubernetes.io/allowedProfileNames: docker/default
    seccomp.security.alpha.kubernetes.io/defaultProfileName: docker/default
    apparmor.security.beta.kubernetes.io/allowedProfileNames: runtime/default
    apparmor.security.beta.kubernetes.io/defaultProfileName: runtime/default
spec:
  privileged: false
  volumes:
    - configMap
    - secret
    - emptyDir
    - hostPath
  allowedHostPaths:
    - pathPrefix: "/etc/cni/net.d"
    - pathPrefix: "/etc/kube-flannel"
    - pathPrefix: "/run/flannel"
  readOnlyRootFilesystem: false
  # Users and groups
  runAsUser:
    rule: RunAsAny
  supplementalGroups:
    rule: RunAsAny
  fsGroup:
    rule: RunAsAny
  # Privilege Escalation
  allowPrivilegeEscalation: false
  defaultAllowPrivilegeEscalation: false
  # Capabilities
  allowedCapabilities: ['NET_ADMIN']
  defaultAddCapabilities: []
  requiredDropCapabilities: []
  # Host namespaces
  hostPID: false
  hostIPC: false
  hostNetwork: true
  hostPorts:
  - min: 0
    max: 65535
  # SELinux
  seLinux:
    # SELinux is unsed in CaaSP
    rule: 'RunAsAny'
---
kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1beta1
metadata:
  name: flannel
rules:
  - apiGroups: ['extensions']
    resources: ['podsecuritypolicies']
    verbs: ['use']
    resourceNames: ['psp.flannel.unprivileged']
  - apiGroups:
      - ""
    resources:
      - pods
    verbs:
      - get
  - apiGroups:
      - ""
    resources:
      - nodes
    verbs:
      - list
      - watch
  - apiGroups:
      - ""
    resources:
      - nodes/status
    verbs:
      - patch
---
kind: ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1beta1
metadata:
  name: flannel
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: flannel
subjects:
- kind: ServiceAccount
  name: flannel
  namespace: kube-system
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: flannel
  namespace: kube-system
---
kind: ConfigMap
apiVersion: v1
metadata:
  name: kube-flannel-cfg
  namespace: kube-system
  labels:
    tier: node
    app: flannel
data:
  cni-conf.json: |
    {
      "name": "cbr0",
      "cniVersion": "0.3.1",
      "plugins": [
        {
          "type": "flannel",
          "delegate": {
            "hairpinMode": true,
            "isDefaultGateway": true
          }
        },
        {
          "type": "portmap",
          "capabilities": {
            "portMappings": true
          }
        }
      ]
    }
  net-conf.json: |
    {
      "Network": "192.168.0.0/16",
      "Backend": {
        "Type": "vxlan"
      }
    }
---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: kube-flannel-ds-amd64
  namespace: kube-system
  labels:
    tier: node
    app: flannel
spec:
  selector:
    matchLabels:
      app: flannel
  template:
    metadata:
      labels:
        tier: node
        app: flannel
    spec:
      hostNetwork: true
      nodeSelector:
        beta.kubernetes.io/arch: amd64
      tolerations:
      - operator: Exists
        effect: NoSchedule
      serviceAccountName: flannel
      initContainers:
      - name: install-cni
        image: quay.io/coreos/flannel:v0.13.1-rc1
        command:
        - cp
        args:
        - -f
        - /etc/kube-flannel/cni-conf.json
        - /etc/cni/net.d/10-flannel.conflist
        volumeMounts:
        - name: cni
          mountPath: /etc/cni/net.d
        - name: flannel-cfg
          mountPath: /etc/kube-flannel/
      containers:
      - name: kube-flannel
        image: quay.io/coreos/flannel:v0.13.1-rc1
        command:
        - /opt/bin/flanneld
        args:
        - --ip-masq
        - --kube-subnet-mgr
        resources:
          requests:
            cpu: "100m"
            memory: "50Mi"
          limits:
            cpu: "100m"
            memory: "50Mi"
        securityContext:
          privileged: false
          capabilities:
             add: ["NET_ADMIN"]
        env:
        - name: POD_NAME
          valueFrom:
            fieldRef:
              fieldPath: metadata.name
        - name: POD_NAMESPACE
          valueFrom:
            fieldRef:
              fieldPath: metadata.namespace
        volumeMounts:
        - name: run
          mountPath: /run/flannel
        - name: flannel-cfg
          mountPath: /etc/kube-flannel/
      volumes:
        - name: run
          hostPath:
            path: /run/flannel
        - name: cni
          hostPath:
            path: /etc/cni/net.d
        - name: flannel-cfg
          configMap:
            name: kube-flannel-cfg
```

	需要注意根据实际情况修改三处位置
	* net-conf.json中的"Network": "192.168.0.0/16"网段地址，需要修改为与kubernentes安装时pod-network-cidr参数相同
	* 修改image: quay.io/coreos/flannel:v0.13.1-rc1的镜像Tag，存在两处。


步骤2. 执行`kubectl apply -f flannal.yaml`，应用flannal配置

步骤3. 再次查看节点状态，已经变更为Ready状态



### 解决调度时不在master节点安装pod的问题
#### 问题现象
默认配置下Kubernetes不会将Pod调度到Master节点。单节点创建deployment迟迟无法履行。

#### 解决方法

执行命令，去除master节点的污点配置

```kubectl taint node dggphicprd09484 node-role.kubernetes.io/master-```

详见：[[2]][Kubernetes污点与容忍度]



## Node节点安装

待补充



# 常见问题

## 恢复master节点的污点配置
```
kubectl taint node dggphicprd09484 node-role.kubernetes.io/master="":NoSchedule
```


## 如何手工恢复环境
```SHELL
rm /var/lib/etcd/* -rf
rm /etc/kubernetes/* -rf
rm /etc/cni/net.d/* -rf
rm ~/.kube/* -rf

#停止所有容器
docker ps | grep -v IMAGE | awk '{print $1}' | xargs docker stop
#删除所有容器
docker ps -a | grep -v IMAGE | awk '{print $1}' | xargs docker rm

systemctl stop kubelet

```

## 查看已安装环境的pod_network_cidr参数
```kubectl describe cm kubeadm-config -n kube-system | grep podSubnet```


## CentOS环境Docker运行容器时报错信息error: runc: undefined symbol: seccomp_api_get
由于CentOS缺少seccomp相关的软件包导致，安装libseccomp-devel软件包即可
```
yum install libseccomp-devel
```



# 参考
EulerOS x86 离线安装 K8s  
http://3ms.huawei.com/km/blogs/details/9692441

Kubernetes(一) 跟着官方文档从零搭建K8S  
https://juejin.cn/post/6844903943051411469

Docker从入门到实践 
https://yeasy.gitbook.io/docker_practice/

Flannal配置详解  
https://www.cnblogs.com/breezey/p/9419612.html


Kubernetes搭建之kubeadm-init探究  
https://juejin.cn/post/6844903728181411848


附录
---

[容器运行时]: https://kubernetes.io/zh/docs/setup/production-environment/container-runtimes/ "容器运行时"
[Kubernetes污点与容忍度]: https://kubernetes.io/zh/docs/concepts/scheduling-eviction/taint-and-toleration/ "Kubernetes污点与容忍度"
[kube-flannal.yaml]: https://github.com/flannel-io/flannel/blob/d893bcbfe6b04791054aea6c7569dea4080cc289/Documentation/kube-flannel.yml "kube-flannal.yaml"
[Docker简明教程]: https://jiajially.gitbooks.io/dockerguide/content/index.html "Docker简明教程"
[Kubernetes 中文指南]: https://jimmysong.io/kubernetes-handbook/ "Kubernetes 中文指南/云原生应用架构实践手册"
[CNI版本号规范]: https://www.cni.dev/docs/spec-upgrades/ "CNI版本号规范"
