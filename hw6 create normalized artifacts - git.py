"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'Filter_SRC_or_DST_Addresses' block
    Filter_SRC_or_DST_Addresses(container=container)

    return

def Filter_SRC_or_DST_Addresses(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Filter_SRC_or_DST_Addresses() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.sourceAddress", "!=", ""],
        ],
        name="Filter_SRC_or_DST_Addresses:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Build_Src_List(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.destinationAddress", "!=", ""],
        ],
        name="Filter_SRC_or_DST_Addresses:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        Build_Dst_List(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return

def Build_Src_List(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Build_Src_List() called')
    
    filtered_artifacts_data_0 = phantom.collect2(container=container, datapath=['filtered-data:Filter_SRC_or_DST_Addresses:condition_1:artifact:*.cef.sourceAddress'])

    parameters = []

    for item0 in filtered_artifacts_data_0:
        parameters.append({
            'input_string': item0[0],
        })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/split_string_list", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/split_string_list', parameters=parameters, name='Build_Src_List', callback=IP_Type_Src_Check)

    return

def Build_Dst_List(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Build_Dst_List() called')
    
    filtered_artifacts_data_0 = phantom.collect2(container=container, datapath=['filtered-data:Filter_SRC_or_DST_Addresses:condition_2:artifact:*.cef.destinationAddress'])

    parameters = []

    for item0 in filtered_artifacts_data_0:
        parameters.append({
            'input_string': item0[0],
        })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/split_string_list", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/split_string_list', parameters=parameters, name='Build_Dst_List', callback=IP_Type_Dst_Check)

    return

"""
Sets ip_type to "public" or "private" based on input
"""
def IP_Type_Src_Check(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('IP_Type_Src_Check() called')
    
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['Build_Src_List:custom_function_result.data.*.element'], action_results=results)
    custom_function_results_item_1_0 = [item[0] for item in custom_function_results_data_1]

    IP_Type_Src_Check__private_ips = None
    IP_Type_Src_Check__public_ips = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    from ipaddress import ip_address
    
    private_ips = []
    public_ips = []
    
    for ip in custom_function_results_item_1_0:
        if ip:
            if (ip_address(ip).is_private):
                private_ips.append(ip)
            else:
                public_ips.append(ip)

    phantom.debug("private ips: {}".format(private_ips))
    phantom.debug("public ips: {}".format(public_ips))

    IP_Type_Src_Check__private_ips = private_ips
    IP_Type_Src_Check__public_ips = public_ips    

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='IP_Type_Src_Check:private_ips', value=json.dumps(IP_Type_Src_Check__private_ips))
    phantom.save_run_data(key='IP_Type_Src_Check:public_ips', value=json.dumps(IP_Type_Src_Check__public_ips))
    create_private_src_artifacts(container=container)
    create_public_src_artifacts(container=container)

    return

"""
Sets ip_type to "public" or "private" based on input
"""
def IP_Type_Dst_Check(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('IP_Type_Dst_Check() called')
    
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['Build_Dst_List:custom_function_result.data.*.element'], action_results=results)
    custom_function_results_item_1_0 = [item[0] for item in custom_function_results_data_1]

    IP_Type_Dst_Check__private_ips = None
    IP_Type_Dst_Check__public_ips = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    from ipaddress import ip_address
    
    private_ips = []
    public_ips = []
    
    for ip in custom_function_results_item_1_0:
        if ip:
            if (ip_address(ip).is_private):
                private_ips.append(ip)
            else:
                public_ips.append(ip)
                
    phantom.debug("private ips: {}".format(private_ips))
    phantom.debug("public ips: {}".format(public_ips))

    IP_Type_Dst_Check__private_ips = private_ips
    IP_Type_Dst_Check__public_ips = public_ips

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='IP_Type_Dst_Check:private_ips', value=json.dumps(IP_Type_Dst_Check__private_ips))
    phantom.save_run_data(key='IP_Type_Dst_Check:public_ips', value=json.dumps(IP_Type_Dst_Check__public_ips))
    create_private_dst_artifacts(container=container)
    create_public_dst_artifacts(container=container)

    return

def create_private_src_artifacts(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('create_private_src_artifacts() called')
    
    IP_Type_Src_Check__private_ips = json.loads(phantom.get_run_data(key='IP_Type_Src_Check:private_ips'))

    ################################################################################
    ## Custom Code Start
    ################################################################################

    phantom.debug("creating src private artifact for {}".format(IP_Type_Src_Check__private_ips))
    
    for ip in IP_Type_Src_Check__private_ips:
        if ip:
            cef = {'deviceAddress': ip, 'sourceAddress': ip, 'cs1': 'private', 'cs2': 'src'}
            phantom.add_artifact(container=container, raw_data=None, cef_data=cef, label='hw6', name='ip artifact', severity='low', run_automation=False)

    ################################################################################
    ## Custom Code End
    ################################################################################
    private_src_filter(container=container)

    return

def create_public_src_artifacts(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('create_public_src_artifacts() called')
    
    IP_Type_Src_Check__public_ips = json.loads(phantom.get_run_data(key='IP_Type_Src_Check:public_ips'))

    ################################################################################
    ## Custom Code Start
    ################################################################################

    phantom.debug("creating src public artifact for {}".format(IP_Type_Src_Check__public_ips))

    for ip in IP_Type_Src_Check__public_ips:
        if ip:
            cef = {'deviceAddress': ip, 'sourceAddress': ip, 'cs1': 'public', 'cs2': 'src'}
            phantom.add_artifact(container=container, raw_data=None, cef_data=cef, label='hw6', name='ip artifact', severity='low', run_automation=False)

    ########
    ########
    ################################################################################
    ## Custom Code End
    ################################################################################
    public_src_filter(container=container)

    return

def create_private_dst_artifacts(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('create_private_dst_artifacts() called')
    
    IP_Type_Dst_Check__private_ips = json.loads(phantom.get_run_data(key='IP_Type_Dst_Check:private_ips'))

    ################################################################################
    ## Custom Code Start
    ################################################################################

    for ip in IP_Type_Dst_Check__private_ips:
        if ip:
            cef = {'deviceAddress': ip, 'destinationAddress': ip, 'cs1': 'private', 'cs2': 'dst'}
            phantom.add_artifact(container=container, raw_data=None, cef_data=cef, label='hw6', name='ip artifact', severity='low', run_automation=False)

    ################################################################################
    ## Custom Code End
    ################################################################################
    private_dst_filter(container=container)

    return

def create_public_dst_artifacts(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('create_public_dst_artifacts() called')
    
    IP_Type_Dst_Check__public_ips = json.loads(phantom.get_run_data(key='IP_Type_Dst_Check:public_ips'))

    ################################################################################
    ## Custom Code Start
    ################################################################################

    phantom.debug("creating dst public artifact for {}".format(IP_Type_Dst_Check__public_ips))

    for ip in IP_Type_Dst_Check__public_ips:
        if ip:
            cef = {'deviceAddress': ip, 'destinationAddress': ip, 'cs1': 'public', 'cs2': 'dst'}
            phantom.add_artifact(container=container, raw_data=None, cef_data=cef, label='hw6', name='ip artifact', severity='low', run_automation=False)

    ################################################################################
    ## Custom Code End
    ################################################################################
    public_dst_filter(container=container)

    return

def private_src_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('private_src_filter() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.cef.deviceAddress", "!=", ""],
            ["artifact:*.cef.cs1", "==", "private"],
            ["artifact:*.cef.sourceAddress", "!=", ""],
        ],
        logical_operator='and',
        name="private_src_filter:condition_1",
        scope="all")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        delay_execution_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def delay_execution_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('delay_execution_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'delay_execution_1' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:private_src_filter:condition_1:artifact:*.id', 'filtered-data:private_src_filter:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'delay_execution_1' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        parameters.append({
            'action': "local/hw6 print address message",
            'artifact_id': filtered_artifacts_item_1[0],
            'action_scope': "artifact",
            'delay_purpose': "create artifact for each private src ip",
            'duration_unit': "Minutes",
            'delay_duration': 1,
            # context (artifact id) is added to associate results with the artifact
            'context': {'artifact_id': filtered_artifacts_item_1[1]},
        })

    phantom.act(action="delay execution", parameters=parameters, assets=['waiter'], name="delay_execution_1")

    return

def public_src_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('public_src_filter() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.cef.deviceAddress", "!=", ""],
            ["artifact:*.cef.cs1", "==", "public"],
            ["artifact:*.cef.sourceAddress", "!=", ""],
        ],
        logical_operator='and',
        name="public_src_filter:condition_1",
        scope="all")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        delay_execution_2(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def delay_execution_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('delay_execution_2() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'delay_execution_2' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:public_src_filter:condition_1:artifact:*.id', 'filtered-data:public_src_filter:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'delay_execution_2' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        parameters.append({
            'action': "local/hw6 print address message",
            'artifact_id': filtered_artifacts_item_1[0],
            'action_scope': "artifact",
            'delay_purpose': "create artifact for each public src ip",
            'duration_unit': "Minutes",
            'delay_duration': 1,
            # context (artifact id) is added to associate results with the artifact
            'context': {'artifact_id': filtered_artifacts_item_1[1]},
        })

    phantom.act(action="delay execution", parameters=parameters, assets=['waiter'], name="delay_execution_2")

    return

def private_dst_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('private_dst_filter() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.cef.deviceAddress", "!=", ""],
            ["artifact:*.cef.cs1", "==", "private"],
            ["artifact:*.cef.destinationAddress", "!=", ""],
        ],
        logical_operator='and',
        name="private_dst_filter:condition_1",
        scope="all")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        delay_execution_3(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def public_dst_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('public_dst_filter() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.cef.deviceAddress", "!=", ""],
            ["artifact:*.cef.cs1", "==", "public"],
            ["artifact:*.cef.destinationAddress", "!=", ""],
        ],
        logical_operator='and',
        name="public_dst_filter:condition_1",
        scope="all")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        delay_execution_4(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def delay_execution_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('delay_execution_3() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'delay_execution_3' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:private_dst_filter:condition_1:artifact:*.id', 'filtered-data:private_dst_filter:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'delay_execution_3' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        parameters.append({
            'action': "local/hw6 print address message",
            'artifact_id': filtered_artifacts_item_1[0],
            'action_scope': "artifact",
            'delay_purpose': "create artifact for each private dst ip",
            'duration_unit': "Minutes",
            'delay_duration': 1,
            # context (artifact id) is added to associate results with the artifact
            'context': {'artifact_id': filtered_artifacts_item_1[1]},
        })

    phantom.act(action="delay execution", parameters=parameters, assets=['waiter'], name="delay_execution_3")

    return

def delay_execution_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('delay_execution_4() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'delay_execution_4' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:public_dst_filter:condition_1:artifact:*.id', 'filtered-data:public_dst_filter:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'delay_execution_4' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        parameters.append({
            'action': "local/hw6 print address message",
            'artifact_id': filtered_artifacts_item_1[0],
            'action_scope': "artifact",
            'delay_purpose': "process public dst ips",
            'duration_unit': "Minutes",
            'delay_duration': 1,
            # context (artifact id) is added to associate results with the artifact
            'context': {'artifact_id': filtered_artifacts_item_1[1]},
        })

    phantom.act(action="delay execution", parameters=parameters, assets=['waiter'], name="delay_execution_4")

    return

def on_finish(container, summary):
    phantom.debug('on_finish() called')
    # This function is called after all actions are completed.
    # summary of all the action and/or all details of actions
    # can be collected here.

    # summary_json = phantom.get_summary()
    # if 'result' in summary_json:
        # for action_result in summary_json['result']:
            # if 'action_run_id' in action_result:
                # action_results = phantom.get_action_results(action_run_id=action_result['action_run_id'], result_data=False, flatten=False)
                # phantom.debug(action_results)

    return