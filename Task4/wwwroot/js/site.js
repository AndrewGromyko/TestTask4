// Please see documentation at https://docs.microsoft.com/aspnet/core/client-side/bundling-and-minification
// for details on configuring this project to bundle and minify static web assets.

// Write your JavaScript code.

function CheckAll() {
    if ($('.summary-check-box').is(':checked')) {
        $(".customer-check-box").prop("checked", true);
    }
    else {
        $(".customer-check-box").prop("checked", false);
    }
}

function Check() {
    if ($('.customer-check-box').length === $('.customer-check-box:checked:enabled').length) {
        $(".summary-check-box").prop("checked", true);
        $(".summary-check-box").prop("indeterminate", false);
    } else if ($('.customer-check-box:checked:enabled').length > 0) {
        $(".summary-check-box").prop("checked", false);
        $(".summary-check-box").prop("indeterminate", true);
    } else {
        $(".summary-check-box").prop("checked", false);
        $(".summary-check-box").prop("indeterminate", false);
    }
}

function GetCheckedBoxes() {
    var checkboxes = document.getElementsByName("");
    var checkboxesChecked = [];
    // loop over them all
    for (var i = 0; i < checkboxes.length; i++) {
        // And stick the checked ones onto an array...
        if (checkboxes[i].checked) {
            checkboxesChecked.push(checkboxes[i].value);
        }
    }
    $(".action").prop("id", checkboxesChecked.join(" "));
}
