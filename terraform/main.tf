terraform {
	required_providers {
		google = {
			source = "hashicorp/google"
			version = "4.51.0"
		}
	}
}

provider "google" {
	project = "lemur-test-terraform"
}

resource "google_compute_instance" "redirector" {
	count = 1

	name = "http-redirector-${count.index}"
	machine_type = "e2-micro"
	zone = "us-east1-b"

	boot_disk {
		initialize_params {
			image = "ubuntu-minimal-2210-kinetic-amd64-v20230126"
		}
	}

	network_interface {
		network = "default"
		access_config {}
	}
}
