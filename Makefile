KMOD=	i3e_driver
SRCS=	i3e_driver.c i3e_driver.h

DCOPTFLAGS+=	-g -O0	

.include <bsd.kmod.mk>
