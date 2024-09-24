variable "username" {
	default = "lemur_proxymslns"
} 
variable "ssh_pubkey" {
	default = "/home/lemur/.ssh/gcp_compute.pub"
}
variable "project_id" {
	default = "lemur-test-terraform"
}
variable "image" {
	default = "ubuntu-minimal-2210-kinetic-amd64-v20230126"
}
variable "region" {
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
	project     = "${var.project_id}"
	region      = "${var.region}"
}

resource "google_compute_instance" "redirector" {
	count 			= 1
	name       		= "http-redirector-${count.index}"
	machine_type    = "e2-micro"
	can_ip_forward  = false
	zone 			= "${var.region}-b"

	metadata = { 
		ssh-keys = "${var.username}:${file(var.ssh_pubkey)}" 
	}

	boot_disk { 
		initialize_params {
			image = "${var.image}" 
		}
	}

	network_interface {
		network = "default"
		access_config {}
	}
}

# resource "google_compute_disk" "default" {
#   name = "test-disk"
#   type = "pd-ssd"
#   zone = "${var.region}-b"
#   size = 10
# }

