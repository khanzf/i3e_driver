KMOD=	i3e_template_driver
SRCS=	i3e_template_driver.c

DCOPTFLAGS+=	-g -O0	

.include <bsd.kmod.mk>
