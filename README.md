# AWS_Cloud_Solution_For_2_Company_Websites_Using_A_Reverse_Proxy_Technology
To reconstruct the AWS Cloud Solution for two company websites using reverse proxy technology (NGINX), follow these detailed steps:
<img width="673" alt="architecture" src="https://github.com/user-attachments/assets/1c23492a-f86f-493a-826b-044ccab297ed">

---

## **1. Setting up an AWS Sub-Account and Hosted Zone**

### 1.1. **Create a Sub-Account in AWS**

1. **Log in to your AWS Root Account:**
   - Head over to the AWS Management Console (https://aws.amazon.com/console/) and log in with your **Root credentials**.

2. **Create a Sub-account:**
   - Go to **AWS Organizations** (this service allows you to create multiple AWS accounts and organize them under one parent/root account).
   - Click on **Create an account** and follow the prompts.
   - Name the new account **DevOps**.
   - Provide a unique email address that isn’t used for another AWS account (you can create a new email or use aliases like `yourname+aws@yourdomain.com`).
![image](https://github.com/user-attachments/assets/f963a964-e8dc-47a5-b434-f7f50239260a)
 ![image](https://github.com/user-attachments/assets/837bcd3c-ee15-4194-9a6f-daa9b4be729a)

This sub-account will help you segregate DevOps tasks from your root account, providing isolation and better security practices.

### 1.2. **Create a Hosted Zone in AWS Route 53**

1. **Navigate to AWS Route 53:**
   - Route 53 is Amazon's scalable DNS and domain name service.

2. **Create a Hosted Zone:**
   - In Route 53, choose **Hosted Zones** from the left-hand menu and click on **Create Hosted Zone**.
   - Enter your domain name (for example, `yourdomain.com`).
   - Choose **Public Hosted Zone** (this will allow the DNS records to be available to the public).
   - Click **Create**.

3. **Set Name Server (NS) records in your Domain Registrar:**
   - After creating the hosted zone, AWS will give you four **NS (Name Server)** values (something like `ns-XXXX.awsdns-XX.net`).
   - Go to your domain registrar (where you bought the domain, for example, GoDaddy, Namecheap, or Cloudns) and update the **Name Servers** with the values provided by AWS.

This will point your domain’s DNS to Route 53, allowing AWS to handle DNS for your website.

---

## **2. Setting up a Virtual Private Cloud (VPC)**

### 2.1. **Create a VPC**

A **Virtual Private Cloud (VPC)** is an isolated network in AWS where your resources (such as EC2 instances, databases, etc.) will reside. Each VPC is divided into **subnets** (smaller ranges of IPs) that can be public or private.
![image](https://github.com/user-attachments/assets/7135c111-9b74-4d29-b81e-2c9b0241c3ca)

```
aws ec2 create-vpc --cidr-block 10.0.0.0/16
```

- `--cidr-block 10.0.0.0/16`: The CIDR block (Classless Inter-Domain Routing) defines the IP address range for the VPC. Here, `10.0.0.0/16` allows 65,536 IP addresses within this VPC, which should be more than enough for most use cases.

After running this command, you will get an output with the `VPC_ID`. Copy it, as you'll need it in subsequent commands.

### 2.2. **Enable DNS Hostnames for the VPC**

By default, DNS hostnames are not enabled for a VPC. You need this to ensure EC2 instances can be resolved by DNS names.
![image](https://github.com/user-attachments/assets/ae25aced-31c8-4100-8cdc-ee98cf099e53)

```
aws ec2 modify-vpc-attribute --vpc-id <VPC_ID> --enable-dns-hostnames
```

- Replace `<VPC_ID>` with the actual VPC ID from the previous step.

### 2.3. **Create Public and Private Subnets**

A **subnet** is a segment of the VPC's IP address range where you can launch AWS resources. You'll create:
- Public Subnets (accessible from the internet)
- Private Subnets (protected and isolated)

#### Create Public Subnets:

```
aws ec2 create-subnet --vpc-id <VPC_ID> --cidr-block 10.0.1.0/24 --availability-zone us-east-1a
aws ec2 create-subnet --vpc-id <VPC_ID> --cidr-block 10.0.2.0/24 --availability-zone us-east-1b
```

- `--vpc-id <VPC_ID>`: Specify the VPC in which the subnet should be created.
- `--cidr-block 10.0.1.0/24`: This defines a subnet that allows 256 IP addresses (`/24` means 256 IPs).
- `--availability-zone`: This determines which AWS Availability Zone the subnet will reside in (for redundancy and fault tolerance).

#### Create Private Subnets:

Repeat the above command with different CIDR blocks for private subnets:

```
aws ec2 create-subnet --vpc-id <VPC_ID> --cidr-block 10.0.3.0/24 --availability-zone us-east-1a
aws ec2 create-subnet --vpc-id <VPC_ID> --cidr-block 10.0.4.0/24 --availability-zone us-east-1b
```
![image](https://github.com/user-attachments/assets/987cc5df-f844-4100-bec7-a83e54b21e76)


Now you have two public subnets and two private subnets in different availability zones.

### 2.4. **Create Route Tables for Public and Private Subnets**

A **Route Table** contains rules that determine how network traffic is routed within the VPC.

#### Create a Public Route Table:

```
aws ec2 create-route-table --vpc-id <VPC_ID>
```

- This creates a route table, but it doesn't route any traffic yet.

#### Associate Public Subnets with the Public Route Table:

```
aws ec2 associate-route-table --route-table-id <PUBLIC_ROUTE_TABLE_ID> --subnet-id <SUBNET_ID>
```

- `--route-table-id <PUBLIC_ROUTE_TABLE_ID>`: Use the Route Table ID from the previous command.
- `--subnet-id <SUBNET_ID>`: Specify the Subnet ID for your public subnets (run this command for each public subnet).
![image](https://github.com/user-attachments/assets/01ecfbf8-fe5d-4c52-8d78-3e87fb87d3f7)


This command associates the public subnets with the public route table.

### 2.5. **Create an Internet Gateway (IGW)**

An **Internet Gateway** is a VPC component that allows communication between instances in the VPC and the internet.

#### Create an IGW:

```
aws ec2 create-internet-gateway
```

- This will return an `InternetGatewayId`. Copy it, as you'll need it to attach the IGW to the VPC.

#### Attach the IGW to the VPC:

```
aws ec2 attach-internet-gateway --vpc-id <VPC_ID> --internet-gateway-id <IGW_ID>
```
![image](https://github.com/user-attachments/assets/9d408225-7a5d-405f-a2d9-7f7da66e2872)


Now, your VPC is connected to the internet through this IGW.

### 2.6. **Update Public Route Table to Route Internet Traffic**

To allow traffic to flow from the internet to your public subnets, you need to create a route in the public route table.

```
aws ec2 create-route --route-table-id <PUBLIC_ROUTE_TABLE_ID> --destination-cidr-block 0.0.0.0/0 --gateway-id <IGW_ID>
```

- `--destination-cidr-block 0.0.0.0/0`: This route allows traffic to flow to any destination (essentially, the internet).
- `--gateway-id <IGW_ID>`: Specifies the Internet Gateway as the path for this traffic.
![image](https://github.com/user-attachments/assets/7648fb8d-a2f4-48f5-bbaa-a34b7c56d8ad)

Now, your public subnets can send and receive traffic from the internet.

### 2.7. **Create a NAT Gateway**

A **NAT Gateway** is used to allow instances in private subnets to access the internet while preventing the internet from initiating connections to them.

#### Allocate an Elastic IP Address:
![image](https://github.com/user-attachments/assets/e5c9ad50-a3c6-4b5e-bc9b-9e4ad3caaad3)

```
aws ec2 allocate-address
```


- This command will give you an **Elastic IP Address (EIP)** that you can assign to the NAT Gateway.

#### Create the NAT Gateway:
![image](https://github.com/user-attachments/assets/b65c859a-d8ec-4262-8b0e-1d1975130b9e)

```
aws ec2 create-nat-gateway --subnet-id <PUBLIC_SUBNET_ID> --allocation-id <ELASTIC_IP_ID>
```

- `--subnet-id <PUBLIC_SUBNET_ID>`: The NAT Gateway needs to reside in a public subnet.
- `--allocation-id <ELASTIC_IP_ID>`: The EIP allocated in the previous step.

Now, you have a NAT Gateway that will allow instances in private subnets to access the internet securely.

---

## **3. Security Groups Setup**

### 3.1. **Create Security Groups for Load Balancers, Web Servers, and NGINX**

**Security Groups** act as virtual firewalls for your instances, controlling inbound and outbound traffic.

#### Create a Security Group for NGINX:

```
aws ec2 create-security-group --group-name nginx-sg --description "Allow ALB" --vpc-id <VPC_ID>
```

This security group allows traffic from the Application Load Balancer (ALB) to the NGINX server.

#### Create a Security Group for Web Servers:

```
aws ec2 create-security-group --group-name web-sg --description "Allow internal ALB" --vpc-id <VPC_ID>
```

This will allow traffic from the internal load balancer to reach your web servers.

#### Create a Security Group for the Data Layer:

```
aws ec2 create-security-group --group-name data-sg --description "Allow access to RDS and EFS" --vpc-id <VPC_ID>
```
![image](https://github.com/user-attachments/assets/ba54ab0c-d466-4994-8e15-7afcbbfdde28)

This group allows access to resources such as RDS (Relational Database Service) and EFS (Elastic File System).

#### Add Inbound Rules to Security Groups:

For each security group, you need to define specific inbound

 rules:

```
aws ec2 authorize-security-group-ingress --group-id <SG_ID> --protocol tcp --port 80 --cidr 0.0.0.0/0
aws ec2 authorize-security-group-ingress --group-id <SG_ID> --protocol tcp --port 443 --cidr 0.0.0.0/0
```

- This allows HTTP (port 80) and HTTPS (port 443) traffic from any IP address (`0.0.0.0/0`).

---

## **4. Obtaining TLS Certificates from Amazon Certificate Manager (ACM)**

**TLS Certificates** encrypt the traffic between your web servers and the clients. You can obtain free certificates from **Amazon Certificate Manager (ACM)**.

### 4.1. **Request a Wildcard Certificate for Your Domain**

A wildcard certificate covers all subdomains under your domain (e.g., `*.yourdomain.com` will cover `www.yourdomain.com`, `blog.yourdomain.com`, etc.).

```
aws acm request-certificate --domain-name "*.yourdomain.com" --validation-method DNS
```

- `--domain-name "*.yourdomain.com"`: This requests a wildcard certificate for the domain.
- `--validation-method DNS`: You will need to validate the certificate request by adding a DNS record in Route 53.

### 4.2. **Validate the Certificate Request**

- After running the command, ACM will give you a **CNAME record** to add to your hosted zone in Route 53.
- Go to **Route 53**, find your hosted zone, and add the CNAME record to validate the certificate request.

Once the DNS validation is complete (this may take a few minutes), ACM will issue your certificate.

---

## **5. Setting up Amazon Elastic File System (EFS)**

Amazon **EFS** is a managed, scalable file storage system that can be shared among multiple EC2 instances.

### 5.1. **Create an EFS File System**

```
aws efs create-file-system --creation-token <TOKEN> --performance-mode generalPurpose
```

- The **creation token** is just a unique identifier to create the EFS. You can use any string you like.
- **General Purpose performance mode** is recommended for most use cases, especially for websites and applications.

### 5.2. **Create Mount Targets for Each Availability Zone**

Once the file system is created, you need to create **mount targets** (entry points) in each availability zone so that instances in different zones can access the EFS.

```
aws efs create-mount-target --file-system-id <EFS_ID> --subnet-id <SUBNET_ID> --security-groups <SG_ID>
```

- Run this command for each availability zone's subnet (public and private) to make the EFS accessible across your infrastructure.

---

## **6. Setting up Amazon RDS**

Amazon **RDS (Relational Database Service)** allows you to run managed relational databases like MySQL, PostgreSQL, or MariaDB.

![image](https://github.com/user-attachments/assets/d81e2412-4f11-4c2d-95d1-f322e0dd82bb)

### 6.1. **Create a KMS Key for Encryption**

If you want to encrypt your database for security purposes, you need to create a KMS (Key Management Service) key:

```
aws kms create-key --description "KMS key for RDS encryption"
```

- This creates a new encryption key that will be used to secure your RDS instance.

### 6.2. **Create a Subnet Group for RDS**

Since RDS instances reside in private subnets, you need to create a **DB Subnet Group** to manage which subnets the database can be placed in.

```
aws rds create-db-subnet-group --db-subnet-group-name mydbsubnetgroup --subnet-ids <SUBNET1_ID> <SUBNET2_ID> --db-subnet-group-description "Subnet group for RDS"
```

- `--subnet-ids <SUBNET1_ID> <SUBNET2_ID>`: Use the private subnets you created earlier.

### 6.3. **Create an RDS MySQL Instance**

Now that you have your KMS key and subnet group, you can create the RDS instance:

```
aws rds create-db-instance --db-instance-identifier mydbinstance --db-instance-class db.t2.micro --engine mysql --allocated-storage 20 --master-username admin --master-user-password <PASSWORD> --db-subnet-group-name mydbsubnetgroup
```

- `--db-instance-identifier mydbinstance`: A unique identifier for the database instance.
- `--db-instance-class db.t2.micro`: The instance type (t2.micro is the free tier, suitable for small workloads).
- `--engine mysql`: Specifies MySQL as the database engine.
- `--allocated-storage 20`: Allocates 20 GB of storage for the database.
- `--master-username admin`: Sets the administrator username for the database.
- `--master-user-password <PASSWORD>`: Specifies the password for the administrator.
![image](https://github.com/user-attachments/assets/0be236d8-d1f6-4570-b765-30dd7a6e752d)

The RDS instance will now be created in the private subnet group with encryption.

---

## **7. Setting up EC2 Instances for NGINX, Web Servers, and Bastion**

### 7.1. **Create EC2 Instances**

EC2 instances are the virtual servers where you will host your applications and services.

#### Create EC2 Instances for NGINX:

```
aws ec2 run-instances --image-id <AMI_ID> --instance-type t2.micro --key-name <KEY_PAIR> --security-group-ids <SG_ID> --subnet-id <SUBNET_ID>
```

- `--image-id <AMI_ID>`: The Amazon Machine Image (AMI) ID that defines the operating system and software. You can use the official Amazon Linux AMI or a custom one.
- `--instance-type t2.micro`: The instance type (t2.micro is free-tier eligible).
- `--key-name <KEY_PAIR>`: Specifies the name of the key pair for SSH access.
- `--security-group-ids <SG_ID>`: The security group that controls the traffic.
- `--subnet-id <SUBNET_ID>`: The subnet where the instance will be placed.

Repeat the above for NGINX and web servers in public and private subnets, respectively.

### 7.2. **Install NGINX on the NGINX Instance**

Once the instance is running, SSH into the NGINX instance:

```
ssh -i <KEY_PAIR>.pem ec2-user@<INSTANCE_PUBLIC_IP>
```

Install NGINX:

```
sudo yum install -y nginx
```

Start and enable NGINX:

```
sudo systemctl start nginx
sudo systemctl enable nginx
```

Now NGINX is installed and running on the instance.

### 7.3. **Install Apache and PHP for Web Servers**

For WordPress and the tooling website, you'll use **Apache** as the web server with **PHP**.

SSH into each web server and install Apache and PHP:

```
sudo yum install -y httpd php php-mysqlnd
```

Start and enable Apache:

```
sudo systemctl start httpd
sudo systemctl enable httpd
```

Your web servers are now ready to host applications like WordPress.

---

## **8. Create an Application Load Balancer (ALB)**

### 8.1. **Create an External ALB for NGINX**

An **Application Load Balancer (ALB)** distributes incoming traffic across multiple targets (such as EC2 instances). You will create an external ALB for the NGINX reverse proxy.

```
aws elbv2 create-load-balancer --name my-ext-alb --subnets <SUBNET1_ID> <SUBNET2_ID> --security-groups <SG_ID> --scheme internet-facing
```

- `--name my-ext-alb`: The name of the ALB.
- `--subnets <SUBNET1_ID> <SUBNET2_ID>`: The public subnets in which the ALB will be placed.
- `--security-groups <SG_ID>`: The security group that controls traffic to the ALB.
- `--scheme internet-facing`: This makes the ALB public-facing.

#### Attach the ACM Certificate to the ALB:

```
aws elbv2 create-listener --load-balancer-arn <ALB_ARN> --protocol HTTPS --port 443 --certificates CertificateArn=<ACM_CERTIFICATE_ARN>
```

- This command configures the ALB to listen for HTTPS traffic on port 443 and use the TLS certificate from ACM.

### 8.2. **Create an Internal ALB for Web Servers**

Next, create an internal ALB that will route traffic to your web servers:

```
aws elbv2 create-load-balancer --name my-int-alb --subnets <PRIVATE_SUBNET1_ID> <PRIVATE_SUBNET2_ID> --security-groups <SG_ID> --scheme internal
```

- This ALB will only be accessible internally within your VPC.

---

## **9. Autoscaling Groups for Web Servers and NGINX**

**Autoscaling Groups (ASGs)** ensure that you always have the right number of instances running to handle the traffic load.

### 9.1. **Create Launch Templates for Web Servers and NGINX**

A **Launch Template** defines the configuration for instances in an autoscaling group (instance type, AMI, key pair, etc.).

```
aws ec2 create-launch-template --launch-template-name web-launch-template --version-description "WebServerTemplate" --launch-template-data "{\"ImageId\":\"<AMI_ID>\", \"InstanceType\":\"t2.micro\"}"
```

- `--launch-template

-name`: The name of the launch template.
- `--launch-template-data`: The data defining the instance configuration.

Repeat this for NGINX instances.

### 9.2. **Create Autoscaling Groups**

Create autoscaling groups that will automatically scale the number of NGINX and web server instances based on traffic.

```
aws autoscaling create-auto-scaling-group --auto-scaling-group-name nginx-asg --launch-template LaunchTemplateName=nginx-launch-template --min-size 1 --max-size 3 --desired-capacity 1 --vpc-zone-identifier <SUBNETS>
```

- `--launch-template LaunchTemplateName=nginx-launch-template`: Specifies the launch template for NGINX.
- `--min-size 1 --max-size 3`: Specifies the minimum and maximum number of instances.
- `--desired-capacity 1`: Specifies how many instances to run initially.

Repeat this for the web servers' autoscaling group.

---

## **10. Configuring the Reverse Proxy on NGINX**

The NGINX server will act as a **reverse proxy**, forwarding traffic to the internal ALB that routes to your web servers.

### 10.1. **Update NGINX Configuration**

SSH into your NGINX instance and edit the NGINX configuration file:

```
sudo vi /etc/nginx/nginx.conf
```

Add the reverse proxy configuration to forward requests to the internal ALB:

```
server {
    listen 80;
    server_name yourdomain.com;
    
    location / {
        proxy_pass http://<INTERNAL_ALB_DNS>;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

- `proxy_pass http://<INTERNAL_ALB_DNS>`: Forward traffic to the internal ALB’s DNS name.

Save the file and restart NGINX:

```bash
sudo systemctl restart nginx
```

Now, NGINX will forward traffic from the external ALB to the internal ALB, which then routes traffic to the web servers.

---

## **11. Launch WordPress and Tooling Applications**

### 11.1. **Install WordPress**

SSH into your web servers and download WordPress:

```bash
wget https://wordpress.org/latest.tar.gz
tar -xzf latest.tar.gz
sudo mv wordpress /var/www/html/
```

Set the proper permissions:

```bash
sudo chown -R apache:apache /var/www/html/wordpress
sudo chmod -R 755 /var/www/html/wordpress
```

Edit the **wp-config.php** file and configure the database connection to the RDS instance:

```bash
sudo vi /var/www/html/wordpress/wp-config.php
```

Once everything is set up, restart Apache:

```bash
sudo systemctl restart httpd
```

### 11.2. **Install the Tooling Application**

Follow a similar process to install your tooling application on the other web server instance.

---

## **12. Monitoring and Maintenance**

Use **CloudWatch** and **AWS Auto Scaling** to monitor traffic and scale your application as needed. You can set alarms in CloudWatch to trigger autoscaling events when CPU utilization or network traffic exceeds predefined thresholds.
![image](https://github.com/user-attachments/assets/30f30add-94ec-4eed-a294-efa657ad2427)

![image](https://github.com/user-attachments/assets/dcb33a9c-5a76-4af4-a818-28b4be8b54ec)

---

This detailed guide provides a step-by-step breakdown of how to set up a highly available and scalable web infrastructure on AWS, from networking and security to EC2 instances, load balancers, and databases.
