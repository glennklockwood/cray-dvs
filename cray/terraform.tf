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
  name = "dvs-ssh-key-${random_string.uniq.result}"
  public_key = "${file("${var.ssh_key_file}.pub")}"
}

# Unified vm definition
resource "openstack_compute_instance_v2" "dvs" {
  # Note: is there a way to define a local variable rather than copy/pasting
  # this around everywhere?
  name = "dvs${count.index == 0 ? "" : "${count.index}"}"
  count = "${var.nodes}"
  image_name = "${lookup(var.os_image_map, var.distro)}"
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
hostname: dvs${count.index == 0 ? "" : "${count.index}"}
fqdn: dvs${count.index == 0 ? "" : "${count.index}"}.example.com
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
    source = "setup_${var.distro}_vm.sh"
    destination = "/usr/local/bin/setup_${var.distro}_vm.sh"
  }
  provisioner "file" {
    connection {
      type = "ssh"
      user = "root"
      private_key = "${file("${var.ssh_key_file}")}"
    }
    source = "setup_files.sh"
    destination = "/usr/local/bin/setup_files.sh"
  }
  provisioner "remote-exec" {
    connection {
      type = "ssh"
      user = "root"
      private_key = "${file("${var.ssh_key_file}")}"
    }
    inline = <<FIN
      zypper --gpg-auto-import-keys ref
      zypper -n up
      # For SLES15, we need to down-rev kernel-default because some kernel
      # dependencies are not available with version 4.12.14-150.14.2. This
      # code should become a candidate for removal with future kernel versions.
      source /etc/os-release
      if [ "$PRETTY_NAME" == "SUSE Linux Enterprise Server 15" ]; then
        zypper -n in --oldpackage kernel-default=4.12.14-25.28.1
        zypper rm -y kernel-default=4.12.14-150.14.2
        shutdown -r +0
      fi
    FIN
  }
  provisioner "local-exec" {
    command = "echo sleeping to allow the vm to possibly reboot; sleep 30"
  }
  provisioner "remote-exec" {
    connection {
      type = "ssh"
      user = "root"
      private_key = "${file("${var.ssh_key_file}")}"
    }
    inline = [ "sh -x /usr/local/bin/setup_${var.distro}_vm.sh eth0 ${var.nodes}" ]
  }
}

output "addresses" {
  value = "${join(",", openstack_compute_instance_v2.dvs.*.network.0.fixed_ip_v4)}"
}

output "random" {
  value = "${random_string.uniq.result}"
}

resource "null_resource" "final_provisioning" {
  count = "${var.nodes}"
  # probably better as a trigger...
  depends_on = ["openstack_compute_instance_v2.dvs"]

  provisioner "remote-exec" {
    connection {
      type = "ssh"
      host = "${element(openstack_compute_instance_v2.dvs.*.network.0.fixed_ip_v4, count.index)}"
      user = "root"
      private_key = "${file("${var.ssh_key_file}")}"
    }
    inline = [ "sh -x /usr/local/bin/setup_files.sh ${join(",", openstack_compute_instance_v2.dvs.*.network.0.fixed_ip_v4)}" ]
  }
}
