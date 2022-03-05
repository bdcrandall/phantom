"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'filter_1' block
    filter_1(container=container)

    return

def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_1() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.fileHash", "!=", ""],
        ],
        name="filter_1:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        check_cache(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def check_cache(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('check_cache() called')
    
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.fileHash', 'artifact:*.id'])
    container_item_0 = [item[0] for item in container_data]

    check_cache__cacheOperation = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    from datetime import date
    
    # Assign new variables for clarity
    fileHash = container_item_0
    
    # Retrieve list containing cache
    cache = phantom.get_list("virus_total_cache")
    
    # Default operation is to look up info and add it to cache
    cacheOperation = "add"
    
    # Iterate through cache to search for fileHash
    for entry in cache:
        if entry[0] == fileHash:
            # Convert string to date object
            yearMonthDay = entry[2].split("-")
            lastUpdated = date(yearMonthDay[0],yearMonthDay[1],yearMonthDay[2])
            
            if date.today() - lastUpdated > 7:
                # Cached info is older than 7 days and needs to be updated
                cacheOperation = "update"
            else:
                # Cached info is current so just read it
                cacheOperation = "read"
    
    # Return the operation the rest of the playbook will perform
    check_cache__cacheOperation = cacheOperation

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='check_cache:cacheOperation', value=json.dumps(check_cache__cacheOperation))
    decision_2(container=container)

    return

def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_2() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        conditions=[
            ["check_cache:custom_function:cacheOperation", "==", "read"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        join_no_op_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    file_reputation(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def file_reputation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('file_reputation() called')

    # collect data for 'file_reputation' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_1:condition_1:artifact:*.cef.fileHash', 'filtered-data:filter_1:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'file_reputation' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'hash': filtered_artifacts_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="file reputation", parameters=parameters, assets=['virustotal'], callback=join_no_op_1, name="file_reputation")

    return

def no_op_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('no_op_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    parameters = []

    phantom.act(action="no op", parameters=parameters, callback=update_reputation_from_cache, name="no_op_1")

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

def update_reputation_from_cache(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('update_reputation_from_cache() called')
    
    check_cache__cacheOperation = json.loads(phantom.get_run_data(key='check_cache:cacheOperation'))
    results_data_1 = phantom.collect2(container=container, datapath=['file_reputation:action_result.data.*.attributes.last_analysis_stats.malicious'], action_results=results)
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_1:condition_1:artifact:*.cef.fileHash'])
    filtered_artifacts_item_1_0 = [item[0] for item in filtered_artifacts_data_1]
    results_item_1_0 = [item[0] for item in results_data_1]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Use variable names that are easier to follow
    cache_operation = check_cache__cacheOperation
    
    # if cache_operation == "add"
        # insert VT results into cache list
    # elsif cache_operation == "update"
        # pull row from list
        # update contents
        # store back into cache list
    
    # pull results from cache list and update container

    ################################################################################
    ## Custom Code End
    ################################################################################

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