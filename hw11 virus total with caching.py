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
    check_cache__cacheIndex = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    from datetime import date
    
    # Assign new variables for clarity
    fileHash = container_item_0
    
    # Retrieve list containing cache
    success, message, cache = phantom.get_list("virus_total_cache")
    
    # TODO put in error handling here if list can't be retrieved
    
    # Default operation is to look up info and add it to cache
    cacheOperation = "add"
    
    # Default value indicates fileHash is not in the cache
    cacheIndex = -1
        
    # Iterate through cache to search for fileHash
    for entry in range(0, len(cache)):
        if cache[entry][0] == fileHash:
            # Convert string to date object
            yearMonthDay = cache[entry][2].split("-")
            lastUpdated = date(yearMonthDay[0],yearMonthDay[1],yearMonthDay[2])
            
            if date.today() - lastUpdated > 7:
                # Cached info is older than 7 days and needs to be updated
                cacheOperation = "update"
                cacheIndex = entry
                break
            else:
                # Cached info is current so just read it
                cacheOperation = "read"
                cacheIndex = entry
                break
    
    # Return the operation the rest of the playbook will perform
    check_cache__cacheOperation = cacheOperation
    
    # Return the location of the data in the cache
    check_cache__cacheIndex = cacheIndex

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='check_cache:cacheOperation', value=json.dumps(check_cache__cacheOperation))
    phantom.save_run_data(key='check_cache:cacheIndex', value=json.dumps(check_cache__cacheIndex))
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

    phantom.act(action="no op", parameters=parameters, callback=update_cache, name="no_op_1")

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

"""
processes any updates to the cache and returns the file reputation of the hash
"""
def update_cache(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('update_cache() called')
    
    check_cache__cacheOperation = json.loads(phantom.get_run_data(key='check_cache:cacheOperation'))
    check_cache__cacheIndex = json.loads(phantom.get_run_data(key='check_cache:cacheIndex'))
    results_data_1 = phantom.collect2(container=container, datapath=['file_reputation:action_result.summary.malicious', 'file_reputation:action_result.data.*.attributes.meaningful_name', 'file_reputation:action_result.data.*.attributes.last_analysis_date'], action_results=results)
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_1:condition_1:artifact:*.cef.fileHash'])
    filtered_artifacts_item_1_0 = [item[0] for item in filtered_artifacts_data_1]
    results_item_1_0 = [item[0] for item in results_data_1]
    results_item_1_1 = [item[1] for item in results_data_1]
    results_item_1_2 = [item[2] for item in results_data_1]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    from datetime import date

    # Cache Structure
    # file_hash_0, file_name_0, file_analysis_date_0, malicous_value_0, lookup_date_0, lookup_count_0
    # file_hash_1, file_name_1, file_analysis_date_1, malicous_value_1, lookup_date_1, lookup_count_1
    # file_hash_2, file_name_2, file_analysis_date_2, malicous_value_2, lookup_date_2, lookup_count_2
    # ...
    # file_hash_n, file_name_n, file_analysis_date_n, malicous_value_n, lookup_date_n, lookup_count_n

    # Use variable names that are easier to follow
    cacheOperation = check_cache__cacheOperation
    cacheIndex = check_cache__cacheIndex
    fileHash = filtered_artifacts_item_1_0
    fileName = results_item_1_1
    fileReputation = results_item_1_0
    fileLastAnalyzed = results_item_1_2

    # Retrieve list containing cache
    cache = phantom.get_list("virus_total_cache")

    if cacheOperation == "add":
        # Add VT results to cache
        newEntry = []
        newEntry[0] = fileHash
        newEntry[1] = fileName
        newEntry[2] = fileLastAnalyzed
        newEntry[3] = fileReputation
        newEntry[4] = date.today().isoformat()
        # Set counter tracking lookups to 1
        newEntry[5] = 1
        cache.append(newEntry)
        cacheIndex = len(cache) - 1
    elif cacheOperation == "update":
        # Update cache with latest results from VT
        cache[cacheIndex][2] = fileLastAnalyzed
        cache[cacheIndex][3] = fileReputation
        cache[cacheIndex][4] = date.today().isoformat()
        # Increment counter tracking number of times we've looked up this file hash
        cache[cacheIndex][5] = cache[cacheIndex][5] + 1
    
    # Pull results from cache list and update container
    message = "filehash: {0}, fileName: {1}, lastAnalyzed: {2}, malicous: {3}, updated: {4}, lookupCount: {5}".format(
        cache[cacheIndex][0],
        cache[cacheIndex][1],
        cache[cacheIndex][2],
        cache[cacheIndex][3],
        cache[cacheIndex][4],
        cache[cacheIndex][5]
    )
    phantom.add_note(note_type="general", title="VT Cache Results", content=message)

    # TODO set color and criticality

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