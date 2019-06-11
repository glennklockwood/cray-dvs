variable "ssh_key_file" {
  description = "Ssh key to use for the vm's setup in openstack for the root user"
  type = "string"
  default = "~/.ssh/id_rsa.cray_openstack"
}

variable "openstack_network_id" {
  description = "The openstack network uuid to use"
  default = "319881ad-16aa-4454-9c73-c9545732b6b9"
}

variable "nodes" {
  description = "Number of vm's to build"
  type = "string"
  default = "1"
}

variable "os_flavor" {
  description = "openstack flavor for the vm's"
  type = "string"
  default = "highcpu.2"
}

variable "os_image_map" {
  description = "openstack image to use for the vm's"
  type = "map"
  default = {
    sles12sp3 = "SLE 12 SP3"
    sles15sp0 = "SLE 15"
  }
}

# NOTE: This is effectively a key for maps we setup, ref os_image_map
variable "distro" {
  description = "The key for os_image_map to select openstack images"
  type = "string"
  default = "sles15sp0"
}