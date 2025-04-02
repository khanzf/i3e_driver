KMOD=	i3e_driver
SRCS=	i3e_driver.c i3e_driver.h \
	i3e_bus.c i3e_bus.h

DCOPTFLAGS+=	-g -O0	

.include <bsd.kmod.mk>
