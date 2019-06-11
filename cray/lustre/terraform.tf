# Used to append a "random" string to resource names.
provider "random" {}

provider "openstack" {}

# Construct our unique random string for resource names, aptly named "uniq"
resource "random_string" "uniq" {
  length = 8
  special = false
}

# Router from Cray_Network so we can get internal traffic to work.
resource "openstack_networking_router_v2" "router" {
  name = "internal-router-${random_string.uniq.result}"
  admin_state_up = "true"
  external_network_id = "${var.openstack_network_id}"
}

# network security group
resource "openstack_compute_secgroup_v2" "network_sg" {
  name = "network-sg-${random_string.uniq.result}"
  description = "network security group"
}

resource "openstack_networking_secgroup_rule_v2" "network_sg_rule1" {
  direction = "ingress"
  ethertype = "IPv4"
  protocol = "tcp"
  security_group_id = "${openstack_compute_secgroup_v2.network_sg.id}"
  remote_ip_prefix = "0.0.0.0/0"
  port_range_min = 22
  port_range_max = 22
}

resource "openstack_networking_secgroup_rule_v2" "network_sg_rule2" {
  direction = "ingress"
  ethertype = "IPv4"
  protocol = "tcp"
  security_group_id = "${openstack_compute_secgroup_v2.network_sg.id}"
  remote_ip_prefix = "0.0.0.0/0"
  port_range_min = 1
  port_range_max = 65535
}

resource "openstack_networking_secgroup_rule_v2" "network_sg_rule3" {
  direction = "ingress"
  ethertype = "IPv4"
  protocol = "icmp"
  security_group_id = "${openstack_compute_secgroup_v2.network_sg.id}"
  remote_ip_prefix = "0.0.0.0/0"
  port_range_min = 0
  port_range_max = 0
}

resource "openstack_networking_secgroup_rule_v2" "network_sg_rule5" {
  direction = "egress"
  ethertype = "IPv4"
  protocol = "tcp"
  security_group_id = "${openstack_compute_secgroup_v2.network_sg.id}"
  remote_ip_prefix = "0.0.0.0/0"
  port_range_min = 1
  port_range_max = 65535
}

resource "openstack_networking_secgroup_rule_v2" "network_sg_rule6" {
  direction = "egress"
  ethertype = "IPv4"
  protocol = "udp"
  security_group_id = "${openstack_compute_secgroup_v2.network_sg.id}"
  remote_ip_prefix = "0.0.0.0/0"
  port_range_min = 1
  port_range_max = 65535
}

resource "openstack_networking_secgroup_rule_v2" "network_sg_rule7" {
  direction = "egress"
  ethertype = "IPv4"
  protocol = "icmp"
  security_group_id = "${openstack_compute_secgroup_v2.network_sg.id}"
  remote_ip_prefix = "0.0.0.0/0"
  port_range_min = 0
  port_range_max = 0
}

resource "openstack_networking_secgroup_rule_v2" "network_sg_rule8" {
  direction = "egress"
  ethertype = "IPv4"
  protocol = "icmp"
  security_group_id = "${openstack_compute_secgroup_v2.network_sg.id}"
  remote_ip_prefix = "0.0.0.0/0"
  port_range_min = 8
  port_range_max = 0
}

# Take the variable that specifies the ssh key and create a keypair
# to use.
resource "openstack_compute_keypair_v2" "terraform" {
  name = "dvs-ci-lustre-ssh-key-${random_string.uniq.result}"
  public_key = "${file("${var.ssh_key_file}.pub")}"
}

# sles15sp0 lustre build vm
resource "openstack_compute_instance_v2" "sles15sp0" {
  # Note: is there a way to define a local variable rather than copy/pasting
  # this around everywhere?
  name = "sles15sp0"
  count = 1
  image_name = "${lookup(var.os_image_map, "sles15sp0")}"
  flavor_name = "${var.os_flavor}"
  network = {
    uuid = "${var.openstack_network_id}"
  }
  key_pair = "${openstack_compute_keypair_v2.terraform.name}"
  security_groups = ["${openstack_compute_secgroup_v2.network_sg.name}"]
  user_data = <<EOF
#cloud-config
system_info:
  default_user:
    name: root
hostname: sles15sp0
fqdn: sles15sp0.example.com
EOF

  # Setup ssh keys first from the ssh key the user provided
  provisioner "file" {
    connection {
      type = "ssh"
      user = "root"
      private_key = "${file("${var.ssh_key_file}")}"
    }
    source = "${var.ssh_key_file}"
    destination = "/root/id_rsa"
  }
  provisioner "file" {
    connection {
      type = "ssh"
      user = "root"
      private_key = "${file("${var.ssh_key_file}")}"
    }
    source = "${var.ssh_key_file}.pub"
    destination = "/root/id_rsa.pub"
  }
  provisioner "remote-exec" {
    connection {
      type = "ssh"
      user = "root"
      private_key = "${file("${var.ssh_key_file}")}"
    }
    inline = [
      "install -dm600 /root/.ssh",
      "mv /root/id_rsa.pub /root/id_rsa /root/.ssh",
      "chmod 400 /root/.ssh/id_rsa.pub /root/.ssh/id_rsa",
      "cat /root/.ssh/id_rsa.pub | tee -a /root/.ssh/authorized_keys"
    ]
  }

  # Setup vm local files
  provisioner "file" {
    connection {
      type = "ssh"
      user = "root"
      private_key = "${file("${var.ssh_key_file}")}"
    }
    source = "lustre.tar"
    destination = "/tmp/lustre.tar"
  }
  provisioner "file" {
    connection {
      type = "ssh"
      user = "root"
      private_key = "${file("${var.ssh_key_file}")}"
    }
    source = "make-lustre-great-again.patch"
    destination = "/tmp/make-lustre-great-again.patch"
  }
  provisioner "file" {
    connection {
      type = "ssh"
      user = "root"
      private_key = "${file("${var.ssh_key_file}")}"
    }
    source = "build_lustre.sh"
    destination = "/usr/local/bin/build_lustre.sh"
  }
  provisioner "remote-exec" {
    connection {
      type = "ssh"
      user = "root"
      private_key = "${file("${var.ssh_key_file}")}"
    }
    inline = [
      "zypper --gpg-auto-import-keys ref",
      "zypper -n up",
      "zypper -n in --oldpackage kernel-default=4.12.14-25.28.1",
      "zypper rm -y kernel-default=4.12.14-150.14.2",
      "shutdown -r +0"
    ]
  }
  provisioner "local-exec" {
    command = "echo sleeping to allow the SLES 15 vm to reboot; sleep 30"
  }
  provisioner "remote-exec" {
    connection {
      type = "ssh"
      user = "root"
      private_key = "${file("${var.ssh_key_file}")}"
    }
    inline = [ "sh -x /usr/local/bin/build_lustre.sh" ]
  }
  # terraform is lame, no builtin way to copy FROM external to local
  provisioner "local-exec" {
    command = "rsync -avz -e 'ssh ${openstack_compute_instance_v2.sles15sp0.network.0.fixed_ip_v4} -i ${var.ssh_key_file} -l root -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null' :/tmp/lustre/ sles15sp0"
  }
}

output "sles15sp0" {
  value = "${openstack_compute_instance_v2.sles15sp0.network.0.fixed_ip_v4}"
}

# sles12sp3 lustre build vm
resource "openstack_compute_instance_v2" "sles12sp3" {
  # Note: is there a way to define a local variable rather than copy/pasting
  # this around everywhere?
  name = "sles12sp3"
  count = 1
  image_name = "${lookup(var.os_image_map, "sles12sp3")}"
  flavor_name = "${var.os_flavor}"
  network = {
    uuid = "${var.openstack_network_id}"
  }
  key_pair = "${openstack_compute_keypair_v2.terraform.name}"
  security_groups = ["${openstack_compute_secgroup_v2.network_sg.name}"]
  user_data = <<EOF
#cloud-config
system_info:
  default_user:
    name: root
hostname: sles12sp3
fqdn: sles12sp3.example.com
EOF

  # Setup ssh keys first from the ssh key the user provided
  provisioner "file" {
    connection {
      type = "ssh"
      user = "root"
      private_key = "${file("${var.ssh_key_file}")}"
    }
    source = "${var.ssh_key_file}"
    destination = "/root/id_rsa"
  }
  provisioner "file" {
    connection {
      type = "ssh"
      user = "root"
      private_key = "${file("${var.ssh_key_file}")}"
    }
    source = "${var.ssh_key_file}.pub"
    destination = "/root/id_rsa.pub"
  }
  provisioner "remote-exec" {
    connection {
      type = "ssh"
      user = "root"
      private_key = "${file("${var.ssh_key_file}")}"
    }
    inline = [
      "install -dm600 /root/.ssh",
      "mv /root/id_rsa.pub /root/id_rsa /root/.ssh",
      "chmod 400 /root/.ssh/id_rsa.pub /root/.ssh/id_rsa",
      "cat /root/.ssh/id_rsa.pub | tee -a /root/.ssh/authorized_keys"
    ]
  }

  # Setup vm local files
  provisioner "file" {
    connection {
      type = "ssh"
      user = "root"
      private_key = "${file("${var.ssh_key_file}")}"
    }
    source = "lustre.tar"
    destination = "/tmp/lustre.tar"
  }
  provisioner "file" {
    connection {
      type = "ssh"
      user = "root"
      private_key = "${file("${var.ssh_key_file}")}"
    }
    source = "make-lustre-great-again.patch"
    destination = "/tmp/make-lustre-great-again.patch"
  }
  provisioner "file" {
    connection {
      type = "ssh"
      user = "root"
      private_key = "${file("${var.ssh_key_file}")}"
    }
    source = "build_lustre.sh"
    destination = "/usr/local/bin/build_lustre.sh"
  }
  provisioner "remote-exec" {
    connection {
      type = "ssh"
      user = "root"
      private_key = "${file("${var.ssh_key_file}")}"
    }
    inline = [ "sh -x /usr/local/bin/build_lustre.sh" ]
  }
  # terraform is lame, no builtin way to copy FROM external to local
  provisioner "local-exec" {
    command = "rsync -avz -e 'ssh ${openstack_compute_instance_v2.sles12sp3.network.0.fixed_ip_v4} -i ${var.ssh_key_file} -l root -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null' :/tmp/lustre/ sles12sp3"
  }
}

output "sles12sp3" {
  value = "${openstack_compute_instance_v2.sles12sp3.network.0.fixed_ip_v4}"
}
