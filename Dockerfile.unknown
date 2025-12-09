FROM ubuntu:24.04


# Copying in the target program source code
RUN mkdir /target
COPY fw.bin /target
COPY regs.txt /target
COPY rom.bin /target
COPY sram.bin /target
COPY asg2.py /target
 
# COPY js.c /target

# TODO: Complete this Dockerfile.
# Carry out all necessary steps to clone, build, and install AFL++,
# and compile the target js.c for fuzzing with AFL++

# Install dependencies
RUN apt-get update && apt-get -y install --no-install-recommends \
    python3 python3-pip \
 && rm -rf /var/lib/apt/lists/*

RUN pip install --break-system-packages unicorn

WORKDIR /target


