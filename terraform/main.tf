variable "gce_ssh_user" {
	default = "lemur_proxymslns"
} 
variable "gce_ssh_pub_key_file" {
	default = "/home/kali/.ssh/gcp_compute.pub"
}
variable "gce_project_id" {
	default = "lemur-test-terraform"
}
variable "gce_image" {
	default = "ubuntu-minimal-2210-kinetic-amd64-v20230126"
}
variable "gce_region" {
	default = "us-east1"
}

terraform {
	required_providers {
		google = {
			source = "hashicorp/google"
			version = "4.51.0"
		}
	}
}

provider "google" {
	project     = "${var.gce_project_id}"
	region      = "${var.gce_region}"
}

resource "google_compute_disk" "default" {
	name = "test-disk"
	type = "pd-ssd"
	zone = "${var.gce_region}-b"
	size = 10
}

resource "google_compute_instance" "redirector" {
	count 			= 1
	name       		= "http-redirector-${count.index}"
	machine_type    = "e2-micro"
	can_ip_forward  = false
	zone 			= "${var.gce_region}-b"

	metadata = { 
		ssh-keys = "${var.gce_ssh_user}:${file(var.gce_ssh_pub_key_file)}" 
	}

	boot_disk { 
		initialize_params {
			image = "${var.gce_image}" 
		}
	}

	network_interface {
		network = "default"
		access_config {}
	}
}
