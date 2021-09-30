// Function to copy URL
function copy(id = 'url')
{
    // Getting the value of the url tag
    var text = document.getElementById(id).innerText;
    // Making a new text area
    var elem = document.createElement("textarea");
    // Adding text area to the document
    document.body.appendChild(elem);
    // Adding the url value to the document
    elem.value = text;
    // Selecting the element to copy
    elem.select();
    // Copying the text
    document.execCommand("copy");
    // Removing the new text area
    document.body.removeChild(elem);
    // Changing the button's text
    document.getElementById('link').innerText = 'Copied!';
}