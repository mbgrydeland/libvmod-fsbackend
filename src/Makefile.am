AM_CPPFLAGS = @VMOD_INCLUDES@ -Wall -Werror

vmoddir = @VMOD_DIR@
vmod_LTLIBRARIES = libvmod_fsbackend.la

libvmod_fsbackend_la_LDFLAGS = -module -export-dynamic -avoid-version -shared

libvmod_fsbackend_la_SOURCES = \
	vcc_if.c \
	vcc_if.h \
	vmod_fsbackend.c

dist_man_MANS = vmod_fsbackend.3
MAINTAINERCLEANFILES = $(dist_man_MANS)

BUILT_SOURCES = vcc_if.c vcc_if.h vmod_fsbackend.man.rst

vcc_if.c vcc_if.h vmod_fsbackend.man.rst: \
	@VMODTOOL@ $(top_srcdir)/src/vmod_fsbackend.vcc
	@VMODTOOL@ $(top_srcdir)/src/vmod_fsbackend.vcc

vmod_fsbackend.3: vmod_fsbackend.man.rst

%.1 %.2 %.3 %.4 %.5 %.6 %.7 %.8 %.9:
if HAVE_RST2MAN
	${RST2MAN} $< $@
else
	@echo "======================================="
	@echo "You need rst2man installed to make dist"
	@echo "======================================="
	@false
endif

VMOD_TESTS = $(top_srcdir)/src/tests/*.vtc
.PHONY: $(VMOD_TESTS)

$(top_srcdir)/src/tests/*.vtc:
	@VARNISHTEST@ -Dvarnishd=@VARNISHD@ -Dvmod_topbuild=$(abs_top_builddir) $@

check: $(VMOD_TESTS)

EXTRA_DIST = \
	vmod_fsbackend.man.rst \
	vmod_fsbackend.vcc \
	$(VMOD_TESTS)

CLEANFILES = $(builddir)/vcc_if.c $(builddir)/vcc_if.h
