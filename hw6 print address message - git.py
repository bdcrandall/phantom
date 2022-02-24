"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'lookup_ip_1' block
    lookup_ip_1(container=container)

    return

def generate_message(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('generate_message() called')
    
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.deviceAddress', 'artifact:*.cef.cs1', 'artifact:*.cef.cs2', 'artifact:*.id'])
    results_data_1 = phantom.collect2(container=container, datapath=['lookup_ip_1:action_result.summary.cannonical_name'], action_results=results)
    results_data_2 = phantom.collect2(container=container, datapath=['geolocate_ip_1:action_result.data.*.country_iso_code'], action_results=results)
    container_item_0 = [item[0] for item in container_data]
    container_item_1 = [item[1] for item in container_data]
    container_item_2 = [item[2] for item in container_data]
    results_item_1_0 = [item[0] for item in results_data_1]
    results_item_2_0 = [item[0] for item in results_data_2]

    generate_message__message = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Create new vars for readability
    ip = container_item_0[0]
    ip_type = container_item_1[0]
    end = container_item_2[0]
    dns = results_item_1_0[0]
    geo_code = ""
    if len(results_item_2_0) > 0:
        geo_code = results_item_2_0[0]
    
    phantom.debug("ip: {}".format(ip))
    phantom.debug("ip_type: {}".format(ip_type))
    phantom.debug("end: {}".format(end))
    phantom.debug("dns: {}".format(dns))
    phantom.debug("geo_code: {}".format(geo_code))
    
    # Construct output templates
    private_template = ("------------------------------\n"
                        "IP Address: {0}\n"
                        "End: {1}\n"
                        "DNS Name: {2}")
    public_template = ("------------------------------\n"
                        "IP Address: {0}\n"
                        "End: {1}\n"
                        "DNS Name: {2}\n"
                        "Country of Origin: {3}")

    # Construct the message based on the address type
    #output_message = ""
    message = ""
    if ip_type == "private":
        # use private template
        message = private_template.format(ip, end, dns)
        #"{}\n{}".format(output_message, message)
    else:
        # use public template
        message = public_template.format(ip, end, dns, geo_code)
        #"{}\n{}".format(output_message, message)
    
    #phantom.debug("output_message: {}".format(output_message))
    phantom.debug("message: {}".format(message))
    
    generate_message__message = message

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='generate_message:message', value=json.dumps(generate_message__message))
    add_comment_1(container=container)

    return

def add_comment_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_comment_1() called')

    generate_message__message = json.loads(phantom.get_run_data(key='generate_message:message'))

    phantom.comment(container=container, comment=generate_message__message)

    container = phantom.get_container(container.get('id', None))

    return

def lookup_ip_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('lookup_ip_1() called')

    # collect data for 'lookup_ip_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.deviceAddress', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'lookup_ip_1' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'ip': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="lookup ip", parameters=parameters, assets=['google_dns'], callback=decision_1, name="lookup_ip_1")

    return

def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_1() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.cef.cs1", "==", "public"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        geolocate_ip_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # check for 'elif' condition 2
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.cef.cs1", "==", "private"],
        ])

    # call connected blocks if condition 2 matched
    if matched:
        join_no_op_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

def no_op_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('no_op_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'no_op_1' call

    parameters = []
    
    # build parameters list for 'no_op_1' call
    parameters.append({
        'sleep_seconds': 0,
    })

    phantom.act(action="no op", parameters=parameters, assets=['phantom'], callback=generate_message, name="no_op_1")

    return

def join_no_op_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_no_op_1() called')
    
    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key='join_no_op_1_called'):
        return

    # no callbacks to check, call connected block "no_op_1"
    phantom.save_run_data(key='join_no_op_1_called', value='no_op_1', auto=True)

    no_op_1(container=container, handle=handle)
    
    return

def geolocate_ip_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('geolocate_ip_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'geolocate_ip_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.deviceAddress', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'geolocate_ip_1' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'ip': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="geolocate ip", parameters=parameters, assets=['maxmind'], callback=join_no_op_1, name="geolocate_ip_1")

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