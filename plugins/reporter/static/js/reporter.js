function generateCorrelationReport() {
    function downloadObjectAsJson(data) {
        var i;
        for (i = 0; i < data['reports'].length; i++){
            let exportName = 'detections_' + i;
            let dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(data['reports'][i], null, 2));
            let downloadAnchorNode = document.createElement('a');
            downloadAnchorNode.setAttribute("href", dataStr);
            downloadAnchorNode.setAttribute("download", exportName + ".json");
            document.body.appendChild(downloadAnchorNode); // required for firefox
            downloadAnchorNode.click();
            downloadAnchorNode.remove();
        }
        alert(i + ' reports have been created and downloaded');
    }
    function showconfirmation(data) {
        let num_reports = data['reports'].length;
        if (num_reports === 1){
            alert('1 new detection report has been created')
        } else {
            alert(num_reports + ' new detection reports have been created')
        }
    }

    let selectionOperationID = $('#layer-selection-operation option:selected').attr('value');
    if (selectionOperationID === '') {
        alert("Please select an item in the list!");
    }
    else {
        let agentOutput = document.getElementById('download-output').checked;
        let tan_check = document.getElementById('tanium-check').checked;
        let cor_check = document.getElementById('cortex-check').checked;
        let qra_check = document.getElementById('qradar-check').checked;
        let postData = { 'index': 'operation', 'operation_id': selectionOperationID,
            'tanium': tan_check, 'cortex': cor_check, 'qradar': qra_check };
        if (agentOutput){
            restRequest('POST', postData, downloadObjectAsJson, 'detectionreport');
        } else {
            restRequest('POST', postData, showconfirmation, 'detectionreport')
        }
    }
}

function exportCSV() {
    function downloadCSV(data) {
        var exportedFilenmae = 'testresults.csv' || 'export.csv';
        var blob = new Blob([data], { type: 'text/csv;charset=utf-8;' });
        if (navigator.msSaveBlob) { // IE 10+
            navigator.msSaveBlob(blob, exportedFilenmae);
        } else {
            var link = document.createElement("a");
            if (link.download !== undefined) { // feature detection
                // Browsers that support HTML5 download attribute
                var url = URL.createObjectURL(blob);
                link.setAttribute("href", url);
                link.setAttribute("download", exportedFilenmae);
                link.style.visibility = 'hidden';
                document.body.appendChild(link);
                link.click();
                document.body.removeChild(link);
            }
        }
    }
    let selectionReportId = $('#layer-selection-report option:selected').attr('value');
    if (selectionReportId === '') {
        alert("Please select an item in the list!");
    }
    else {
        let postData = { 'index': 'report', 'report_id': selectionReportId };
        restRequest('POST', postData, downloadCSV, 'CSVexport');
    }
}

function openHelp() {
    document.getElementById("duk-modal-compass").style.display = "block";
}
