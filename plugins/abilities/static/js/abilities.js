function generateAbilities() {

	    function downloadObjectAsCSV(data){

		    let exportName = 'abilities';
		    

		    //let dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(data, null, 2));
		    
		    //var jsonObject = JSON.stringify(data);//, null, 2);
		    var csv = data; //unescape(jsonObject);//.replace(;//convertToCSV(jsonObject);
				
		    

		    //var dataStr = new Blob([csv], { type: 'text/csv;charset=utf-8;' });


		        var exportedFilenmae = 'abilities.csv' || 'export.csv';



		        var blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });

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

		    /*
		    let downloadAnchorNode = document.createElement('a');
		    downloadAnchorNode.setAttribute("href", dataStr);
		    downloadAnchorNode.setAttribute("download", exportName + ".csv");
		    document.body.appendChild(downloadAnchorNode); // required for firefox
		    downloadAnchorNode.click();
		    downloadAnchorNode.remove();
		    */
	        }


	    let selectionAdversaryID = $('#layer-selection-adversary option:selected').attr('value');

	    let postData = selectionAdversaryID ? {'index':'adversary', 'adversary_id': selectionAdversaryID} : {'index': 'all'};

	    restRequest('POST', postData, downloadObjectAsCSV, '/plugin/abilities/csv');

}


function searchTerm(){
	let category = $('#search_category option:selected').attr('value');
	let term = document.getElementById('search_term').value;
	if (category === 'default' || term === ''){
        alert("Please select an item in the list and insert a term")
    } else {
	window.location.search = '&category=' + category + '&term=' + term;
	}
}

function openHelp() {
    document.getElementById("duk-modal-compass").style.display="block";
}