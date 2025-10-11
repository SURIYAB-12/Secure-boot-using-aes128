# RTL Script to run Basic Synthesis Flow
set_db init_lib_search_path /home/install/FOUNDRY/digital/90nm/dig/lib   
set_db hdl_search_path /home/student/Documents/22ecr205
set_db library slow.lib
read_hdl maintest.v
elaborate 
current_design secure_boot_top
read_sdc /home/student/Documents/22ecr205/constraints_sdc.sdc


set_db syn_generic_effort medium
syn_generic
set_db syn_map_effort medium
syn_map
set_db syn_opt_effort medium
syn_opt


write_hdl > OPT_netlist.v
write_sdc > OPT_block.sdc
report_area > OPT_area.rep
report_gates > OPT_gate.rep
report_power > OPT_power.rep
report_timing > OPT_timing.rep
gui_show


