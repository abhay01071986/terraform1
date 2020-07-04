terraform {
 backend "remote" {
   organization = "example-organization"

   workspaces {
     name = "example-workspace"
   }
 }
}

resource "null_resource" "terraform-github-actions" {
 triggers = {
   value = "This resource was created using GitHub Actions!"
 }
}