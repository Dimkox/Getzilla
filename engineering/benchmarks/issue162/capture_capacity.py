from launch import command,base,IMAGE
command('capacity',base('capacity')+[IMAGE,'python','/scripts/observe.py'])
