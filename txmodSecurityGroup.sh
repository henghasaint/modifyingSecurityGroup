#!/bin/bash
API_COM='/usr/bin/tccli vpc ModifySecurityGroupPolicies --cli-unfold-argument --region ap-guangzhou --SecurityGroupId'

date +%F-%T

fileIP='/root/txapi/localIP'
localIP_old=`cat $fileIP`

while true
do
localIP=`timeout 20 curl ifconfig.me`
if [ $? == 0 ];then
  break
fi
done

if [ ${localIP_old} == ${localIP} ];then
        exit
else
        echo $localIP > $fileIP
fi
#知买账号
zhimai(){
#       subuser: security-group
	export TENCENTCLOUD_SECRET_ID=AKIDDH5duud6JFtGNDm58vRP7cqnTs0rRknZ
	export TENCENTCLOUD_SECRET_KEY=WlkSs2wZv0oMcbJkuoRntiHZbMp20h6E
	export TENCENTCLOUD_REGION=ap-guangzhou

	# 501ssh
	${API_COM} "sg-9o77iwrl" \
		--SecurityGroupPolicySet.Ingress.0.Protocol TCP \
		--SecurityGroupPolicySet.Ingress.0.Port 22 \
		--SecurityGroupPolicySet.Ingress.0.CidrBlock ${localIP} \
		--SecurityGroupPolicySet.Ingress.0.Action ACCEPT \
		--SecurityGroupPolicySet.Ingress.0.PolicyDescription 501办公室ip

	# 501web
	${API_COM} "sg-cyc4832d" \
		--SecurityGroupPolicySet.Ingress.0.Protocol TCP \
		--SecurityGroupPolicySet.Ingress.0.Port 80,443,8848 \
		--SecurityGroupPolicySet.Ingress.0.CidrBlock ${localIP} \
		--SecurityGroupPolicySet.Ingress.0.Action ACCEPT \
		--SecurityGroupPolicySet.Ingress.0.PolicyDescription 501办公室ip

	# 501数据库 22862为TDSQL-C端口
	${API_COM} "sg-otjf02fj" \
	        --SecurityGroupPolicySet.Ingress.0.Protocol TCP \
	        --SecurityGroupPolicySet.Ingress.0.Port 3306,22862,6379,8123,9123,9124,9000 \
	        --SecurityGroupPolicySet.Ingress.0.CidrBlock ${localIP} \
	        --SecurityGroupPolicySet.Ingress.0.Action ACCEPT \
	        --SecurityGroupPolicySet.Ingress.0.PolicyDescription 501办公室ip

        # 501yearning 8000为yearning页面端口，22为本地访问
        ${API_COM} "sg-d77q09bh" \
                --SecurityGroupPolicySet.Ingress.0.Protocol TCP \
                --SecurityGroupPolicySet.Ingress.0.Port 22,8000 \
                --SecurityGroupPolicySet.Ingress.0.CidrBlock ${localIP} \
                --SecurityGroupPolicySet.Ingress.0.Action ACCEPT \
                --SecurityGroupPolicySet.Ingress.0.PolicyDescription 501办公室ip

}
#理想动力账号
lxdl(){
	export TENCENTCLOUD_SECRET_ID=AKIDTmtgHfMtEKNDqGzWoshGhXF3ey3uycnn
        export TENCENTCLOUD_SECRET_KEY=oQp0xd7e2GFzWqvpXZP3Sda1FG4dvy5x
        export TENCENTCLOUD_REGION=ap-guangzhou

	${API_COM} "sg-7hiqraf9" \
                --SecurityGroupPolicySet.Ingress.0.Protocol TCP \
                --SecurityGroupPolicySet.Ingress.0.Port 22,3306,80,443,8848 \
                --SecurityGroupPolicySet.Ingress.0.CidrBlock ${localIP} \
                --SecurityGroupPolicySet.Ingress.0.Action ACCEPT \
                --SecurityGroupPolicySet.Ingress.0.PolicyDescription 501办公室ip
}

sendIP(){
     curl "https://oapi.dingtalk.com/robot/send?access_token=515fdf3f7ef7cf7fd9729d9c10235eca9f1f3b26de8077e560d1f328da1af020" \
             -H "Content-Type: application/json" \
             -d "{\"msgtype\":\"text\",\"text\":{
                  \"content\": \"501IP变化：当前IP为${localIP} \n服务器IP为：$(/usr/sbin/ifconfig eth0 | awk 'NR==2' | awk {'print $2'})\"
          }
          }"
}

sendIP
zhimai
lxdl