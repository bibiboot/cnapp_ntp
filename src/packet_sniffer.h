#pragma once

#include "globals.h"
#include "filter.h"
#include "print_packet.h"

#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>

void* sniff(void *val);
