/*
 * Copyright (C) 2008 Martin Willi
 * Hochschule fuer Technik Rapperswil
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>

#include <library.h>
#include <dumm.h>

#undef PACKAGE_NAME
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION
#undef PACKAGE_STRING
#include <ruby.h>

dumm_t *dumm;

VALUE rbm_dumm;
VALUE rbc_guest;
VALUE rbc_bridge;
VALUE rbc_iface;

/**
 * Guest invocation callback
 */
static pid_t invoke(void *null, guest_t *guest, char *args[], int argc)
{
	pid_t pid;
	
	args[argc] = "con0=xterm";
	
	pid = fork();
	switch (pid)
	{
		case 0: /* child */
			dup2(open("/dev/null", 0), 1);
			dup2(open("/dev/null", 0), 2);
			execvp(args[0], args);
			/* FALL */
		case -1:
			rb_raise(rb_eException, "starting guest failed");
			return 0;
		default:
			return pid;
	}
}

/**
 * SIGCHLD signal handler
 */
static void sigchld_handler(int signal, siginfo_t *info, void* ptr)
{
	enumerator_t *enumerator;
	guest_t *guest;
	
	enumerator = dumm->create_guest_enumerator(dumm);
	while (enumerator->enumerate(enumerator, &guest))
	{
		if (guest->get_pid(guest) == info->si_pid)
		{
			guest->sigchild(guest);
			break;
		}
	}
	enumerator->destroy(enumerator);
}

/**
 * Guest bindings
 */
static VALUE guest_get(VALUE class, VALUE key)
{
	enumerator_t *enumerator;
	guest_t *guest, *found = NULL;
	
	enumerator = dumm->create_guest_enumerator(dumm);
	while (enumerator->enumerate(enumerator, &guest))
	{
		if (streq(guest->get_name(guest), StringValuePtr(key)))
		{
			found = guest;
			break;
		}
	}
	enumerator->destroy(enumerator);
	if (!found)
	{
		return Qnil;
	}
	return Data_Wrap_Struct(class, NULL, NULL, found);
}

static VALUE guest_each(int argc, VALUE *argv, VALUE class)
{
	enumerator_t *enumerator;
	guest_t *guest;

	if (!rb_block_given_p())
    {
		rb_raise(rb_eArgError, "must be called with a block");
	}
	enumerator = dumm->create_guest_enumerator(dumm);
	while (enumerator->enumerate(enumerator, &guest))
	{
  		rb_yield(Data_Wrap_Struct(class, NULL, NULL, guest));
	}
	enumerator->destroy(enumerator);
	return Qnil;
}

static VALUE guest_new(VALUE class, VALUE name, VALUE kernel,
					   VALUE master, VALUE mem)

{
	guest_t *guest;
	
	guest = dumm->create_guest(dumm, StringValuePtr(name), StringValuePtr(kernel),
							   StringValuePtr(master), FIX2INT(mem));
	if (!guest)
	{
		return Qnil;
	}
	return Data_Wrap_Struct(class, NULL, NULL, guest);
}

static VALUE guest_to_s(VALUE self)
{
	guest_t *guest;
	
	Data_Get_Struct(self, guest_t, guest);
	return rb_str_new2(guest->get_name(guest));
}

static VALUE guest_start(VALUE self)
{
	guest_t *guest;
	
	Data_Get_Struct(self, guest_t, guest);
	
	if (guest->start(guest, invoke, NULL, NULL))
	{
		return Qtrue;
	}
	return Qfalse;
}

static VALUE guest_stop(VALUE self)
{
	guest_t *guest;
	
	Data_Get_Struct(self, guest_t, guest);
	
	if (guest->stop(guest, NULL))
	{
		return Qtrue;
	}
	return Qfalse;
}

static VALUE guest_add_iface(VALUE self, VALUE name)
{
	guest_t *guest;
	iface_t *iface;
	
	Data_Get_Struct(self, guest_t, guest);
	iface = guest->create_iface(guest, StringValuePtr(name));
	if (iface)
	{
		return Data_Wrap_Struct(rbc_iface, NULL, NULL, iface);
	}
	return Qnil;
}

static VALUE guest_get_iface(VALUE self, VALUE key)
{
	enumerator_t *enumerator;
	iface_t *iface, *found = NULL;
	guest_t *guest;
	
	Data_Get_Struct(self, guest_t, guest);
	enumerator = guest->create_iface_enumerator(guest);
	while (enumerator->enumerate(enumerator, &iface))
	{
		if (streq(iface->get_guestif(iface), StringValuePtr(key)))
		{
			found = iface;
			break;
		}
	}
	enumerator->destroy(enumerator);
	if (!found)
	{
		return Qnil;
	}
	return Data_Wrap_Struct(rbc_iface, NULL, NULL, iface);
}

static VALUE guest_each_iface(int argc, VALUE *argv, VALUE self)
{
	enumerator_t *enumerator;
	guest_t *guest;
	iface_t *iface;

	if (!rb_block_given_p())
    {
		rb_raise(rb_eArgError, "must be called with a block");
	}
	Data_Get_Struct(self, guest_t, guest);
	enumerator = guest->create_iface_enumerator(guest);
	while (enumerator->enumerate(enumerator, &iface))
	{
  		rb_yield(Data_Wrap_Struct(rbc_iface, NULL, NULL, iface));
	}
	enumerator->destroy(enumerator);
	return Qnil;
}

static VALUE guest_delete(VALUE self)
{
	guest_t *guest;
	
	Data_Get_Struct(self, guest_t, guest);
	dumm->delete_guest(dumm, guest);
	return Qnil;
}

static void guest_init()
{
	rbc_guest = rb_define_class_under(rbm_dumm , "Guest", rb_cObject);
	rb_define_singleton_method(rbc_guest, "[]", guest_get, 1);
	rb_define_singleton_method(rbc_guest, "each", guest_each, -1);
	rb_define_singleton_method(rbc_guest, "new", guest_new, 4);
	rb_define_method(rbc_guest, "to_s", guest_to_s, 0);
	rb_define_method(rbc_guest, "start", guest_start, 0);
	rb_define_method(rbc_guest, "stop", guest_stop, 0);
	rb_define_method(rbc_guest, "add", guest_add_iface, 1);
	rb_define_method(rbc_guest, "[]", guest_get_iface, 1);
	rb_define_method(rbc_guest, "each", guest_each_iface, -1);
	rb_define_method(rbc_guest, "delete", guest_delete, 0);
}

/**
 * Bridge binding
 */
static VALUE bridge_get(VALUE class, VALUE key)
{
	enumerator_t *enumerator;
	bridge_t *bridge, *found = NULL;
	
	enumerator = dumm->create_bridge_enumerator(dumm);
	while (enumerator->enumerate(enumerator, &bridge))
	{
		if (streq(bridge->get_name(bridge), StringValuePtr(key)))
		{
			found = bridge;
			break;
		}
	}
	enumerator->destroy(enumerator);
	if (!found)
	{
		return Qnil;
	}
	return Data_Wrap_Struct(class, NULL, NULL, found);
}

static VALUE bridge_each(int argc, VALUE *argv, VALUE class)
{
	enumerator_t *enumerator;
	bridge_t *bridge;

	if (!rb_block_given_p())
    {
		rb_raise(rb_eArgError, "must be called with a block");
	}
	enumerator = dumm->create_bridge_enumerator(dumm);
	while (enumerator->enumerate(enumerator, &bridge))
	{
  		rb_yield(Data_Wrap_Struct(class, NULL, NULL, bridge));
	}
	enumerator->destroy(enumerator);
	return Qnil;
}

static VALUE bridge_new(VALUE class, VALUE name)

{
	bridge_t *bridge;
	
	bridge = dumm->create_bridge(dumm, StringValuePtr(name));
	if (!bridge)
	{
		return Qnil;
	}
	return Data_Wrap_Struct(class, NULL, NULL, bridge);
}

static VALUE bridge_to_s(VALUE self)
{
	bridge_t *bridge;
	
	Data_Get_Struct(self, bridge_t, bridge);
	return rb_str_new2(bridge->get_name(bridge));
}

static VALUE bridge_each_iface(int argc, VALUE *argv, VALUE self)
{
	enumerator_t *enumerator;
	bridge_t *bridge;
	iface_t *iface;

	if (!rb_block_given_p())
    {
		rb_raise(rb_eArgError, "must be called with a block");
	}
	Data_Get_Struct(self, bridge_t, bridge);
	enumerator = bridge->create_iface_enumerator(bridge);
	while (enumerator->enumerate(enumerator, &iface))
	{
  		rb_yield(Data_Wrap_Struct(rbc_iface, NULL, NULL, iface));
	}
	enumerator->destroy(enumerator);
	return Qnil;
}

static VALUE bridge_delete(VALUE self)
{
	bridge_t *bridge;
	
	Data_Get_Struct(self, bridge_t, bridge);
	dumm->delete_bridge(dumm, bridge);
	return Qnil;
}

static void bridge_init()
{
	rbc_bridge = rb_define_class_under(rbm_dumm , "Bridge", rb_cObject);
	rb_define_singleton_method(rbc_bridge, "[]", bridge_get, 1);
	rb_define_singleton_method(rbc_bridge, "each", bridge_each, -1);
	rb_define_singleton_method(rbc_bridge, "new", bridge_new, 1);
	rb_define_method(rbc_bridge, "to_s", bridge_to_s, 0);
	rb_define_method(rbc_bridge, "each", bridge_each_iface, -1);
	rb_define_method(rbc_bridge, "delete", bridge_delete, 0);
}

/**
 * Iface wrapper
 */
static VALUE iface_to_s(VALUE self)
{
	iface_t *iface;
	
	Data_Get_Struct(self, iface_t, iface);
	return rb_str_new2(iface->get_hostif(iface));
}

static VALUE iface_connect(VALUE self, VALUE vbridge)
{
	iface_t *iface;
	bridge_t *bridge;
	
	Data_Get_Struct(self, iface_t, iface);
	Data_Get_Struct(vbridge, bridge_t, bridge);
	if (bridge->connect_iface(bridge, iface))
	{
		return self;
	}
	return Qnil;
}

static VALUE iface_disconnect(VALUE self)
{
	iface_t *iface;
	bridge_t *bridge;
	
	Data_Get_Struct(self, iface_t, iface);
	bridge = iface->get_bridge(iface);
	if (bridge && bridge->disconnect_iface(bridge, iface))
	{
		return self;
	}
	return Qnil;
}

static VALUE iface_delete(VALUE self)
{
	guest_t *guest;
	iface_t *iface;
	
	Data_Get_Struct(self, iface_t, iface);
	guest = iface->get_guest(iface);
	guest->destroy_iface(guest, iface);
	return Qnil;
}

static void iface_init()
{
	rbc_iface = rb_define_class_under(rbm_dumm , "Iface", rb_cObject);
	rb_define_method(rbc_iface, "to_s", iface_to_s, 0);
	rb_define_method(rbc_iface, "connect", iface_connect, 1);
	rb_define_method(rbc_iface, "disconnect", iface_disconnect, 0);
	rb_define_method(rbc_iface, "delete", iface_delete, 0);
}

/**
 * main routine, parses args and reads from console
 */
int main(int argc, char *argv[])
{	
	int state;
	struct sigaction action;
	
	ruby_init();
	ruby_init_loadpath();
	
	/* there are to many to report, rubyruby... */
	setenv("LEAK_DETECTIVE_DISABLE", "1", 1);
	
	library_init(NULL);
	
	dumm = dumm_create(NULL);
	
	rbm_dumm = rb_define_module("Dumm");
	
	guest_init();
	bridge_init();
	iface_init();
	
	sigemptyset(&action.sa_mask);
	action.sa_sigaction = sigchld_handler;
	action.sa_flags = SA_SIGINFO;
	sigaction(SIGCHLD, &action, NULL);

	rb_require("irb");
	rb_eval_string_protect("include Dumm", &state);
	rb_eval_string_protect("IRB.start", &state);
	if (state)
	{
		rb_p(ruby_errinfo);
	}
	
	dumm->destroy(dumm);
	
	action.sa_handler = SIG_DFL;
	action.sa_flags = 0;
	sigaction(SIGCHLD, &action, NULL);
	
	library_deinit();
	return 0;
}

