THIS_DIR:=$(dir $(word $(words $(MAKEFILE_LIST)),$(MAKEFILE_LIST)))

include $(THIS_DIR)../../test.mk