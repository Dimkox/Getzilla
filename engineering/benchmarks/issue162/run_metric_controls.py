from launch import command,base,IMAGE
command('metric-controls',base('metrics')+[IMAGE,'python','/scripts/test_metrics.py'])
