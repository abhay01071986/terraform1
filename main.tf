terraform {
 backend "remote" {
   organization = "abhay_test"

   workspaces {
     name = "terraform"
   }
 }
}

resource "null_resource" "terraform-github-actions" {
 triggers = {
   value = "This resource was created using GitHub Actions!"
 }
}