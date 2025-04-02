#!/bin/bash

# List of target platforms
declare -a platforms=("linux/amd64/" "linux/arm/" "windows/amd64/exe" "darwin/amd64/" "darwin/arm64/" "solaris/amd64/" "aix/amd64")

mkdir binaries

# Build for each platform
for platform in "${platforms[@]}"; do
  # Split the platform string into ${os} and {arch}itecture
  IFS='/' read -ra target <<< "$platform"
  os="${target[0]}"
  arch="${target[1]}"
  extension="${target[2]}"

  # Set the environment variables for the target platform
  export GOOS="${os}"
  export GOARCH="${arch}"

  # Build the Go project

  if [[ -z $extension ]]; then
    output_name="ssl_handshake_${os}_${arch}"    
  else
    output_name="ssl_handshake_${os}_${arch}.${extension}"
  fi

  echo "Building $output_name"
  go build -o binaries/"$output_name"

  echo "Built $output_name"
done
