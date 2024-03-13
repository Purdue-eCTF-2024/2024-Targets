# SPDX-License-Identifier: GPL-2.0-or-later

# Defines basic Tcl procs that must exist for OpenOCD scripts to work.
#
# Embedded into OpenOCD executable
#

# Try flipping / and \ to find file if the filename does not
# match the precise spelling
proc find {filename} {
	if {[catch {ocd_find $filename} t]==0} {
		return $t
	}
	if {[catch {ocd_find [string map {\ /} $filename} t]==0} {
		return $t
	}
	if {[catch {ocd_find [string map {/ \\} $filename} t]==0} {
		return $t
	}
	# make sure error message matches original input string
	return -code error "Can't find $filename"
}
add_usage_text find "<file>"
add_help_text find "print full path to file according to OpenOCD search rules"

# Find and run a script
proc script {filename} {
	uplevel #0 [list source [find $filename]]
}
add_help_text script "filename of OpenOCD script (tcl) to run"
add_usage_text script "<file>"

# Run a list of post-init commands
# Each command should be added with 'lappend post_init_commands command'
lappend _telnet_autocomplete_skip _run_post_init_commands
proc _run_post_init_commands {} {
	if {[info exists ::post_init_commands]} {
		foreach cmd $::post_init_commands {
			eval $cmd
		}
	}
}

# Run a list of pre-shutdown commands
# Each command should be added with 'lappend pre_shutdown_commands command'
lappend _telnet_autocomplete_skip _run_pre_shutdown_commands
proc _run_pre_shutdown_commands {} {
	if {[info exists ::pre_shutdown_commands]} {
		foreach cmd $::pre_shutdown_commands {
			eval $cmd
		}
	}
}

#########
