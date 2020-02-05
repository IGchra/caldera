function generateAdv() {
    function downloadObjectAsJson(data){
        /*
	let exportName = 'layer';
        let dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(data, null, 2));
        let downloadAnchorNode = document.createElement('a');
        downloadAnchorNode.setAttribute("href", dataStr);
        downloadAnchorNode.setAttribute("download", exportName + ".json");
        document.body.appendChild(downloadAnchorNode); // required for firefox
        downloadAnchorNode.click();
        downloadAnchorNode.remove();
	*/
	alert('New Adversary Created.');
    }	    

    let postData = {'category':'tactic', 'term':''}
    restRequest('POST', postData, downloadObjectAsJson, '/plugin/importer/layer');
}

function generateSpecificAdv() {
    function downloadObjectAsJson(data){
        /*
	let exportName = 'layer';
        let dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(data, null, 2));
        let downloadAnchorNode = document.createElement('a');
        downloadAnchorNode.setAttribute("href", dataStr);
        downloadAnchorNode.setAttribute("download", exportName + ".json");
        document.body.appendChild(downloadAnchorNode); // required for firefox
        downloadAnchorNode.click();
        downloadAnchorNode.remove();
	*/
	alert('New Adversary including all abilities with ' + category + ' starting with ' + term + ' created.');
    }	    

    let category = $('#search_category option:selected').attr('value');
    let term = document.getElementById('search_term').value;
    if (category === 'default' || term === ''){
        alert("Please select an item in the list and insert a term")
    } else {
    let postData = {'category': category, 'term': term}
    restRequest('POST', postData, downloadObjectAsJson, '/plugin/importer/layer');
    }
}

function uploadCSVButtonFileUpload() {
    document.getElementById('CSVInput').click();
}
$('#CSVInput').on('change', function (event){
    if(event.currentTarget) {
        let filename = event.currentTarget.files[0].name;
        if(filename){
	    uploadAdversaryLayer();
        }

    }
});

function uploadAdversaryLayer() {
    let file = document.getElementById('CSVInput').files[0];
    let fd = new FormData();
    fd.append('file', file);
    $.ajax({
         type: 'POST',
         url: '/plugin/importer/adversary',
         data: fd,
         processData: false,
         contentType: false
    }).done(function (){
        alert('New Abilities Created.');
    })
}

function openHelp() {
    document.getElementById("duk-modal-compass").style.display="block";
}
