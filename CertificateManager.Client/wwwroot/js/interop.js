window.showAlert = (messaggio) => {
    alert(messaggio);
};

// 👇 Aggiungi la nuova funzione qui sotto 👇
window.downloadFileFromStream = async (fileName, contentStreamReference) => {
    const arrayBuffer = await contentStreamReference.arrayBuffer();
    const blob = new Blob([arrayBuffer]);
    const url = URL.createObjectURL(blob);
    const anchorElement = document.createElement('a');
    anchorElement.href = url;
    anchorElement.download = fileName ?? '';
    anchorElement.click();
    anchorElement.remove();
    URL.revokeObjectURL(url);
};

window.blazorDownloadFileFromArray = (fileName, content) => {

    const arrayBuffer = new Uint8Array(content);
    const blob = new Blob([arrayBuffer]);

    const url = URL.createObjectURL(blob);

    const anchorElement = document.createElement('a');
    anchorElement.href = url;
    anchorElement.download = fileName ?? 'defaultName.default'; // Usa il nome fornito

    document.body.appendChild(anchorElement);
    anchorElement.click();
    anchorElement.remove();

    // Rilascia la memoria
    URL.revokeObjectURL(url);
}