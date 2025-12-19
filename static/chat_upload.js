document.addEventListener('DOMContentLoaded', () => {
    const uploadBtn = document.getElementById('uploadBtn');
    const imageInput = document.getElementById('imageInput');
    const chatForm = document.getElementById('chatForm');


    if(uploadBtn) {
        uploadBtn.addEventListener('click', () => {
            imageInput.click();
        });
    }


    if(imageInput) {
        imageInput.addEventListener('change', () => {
            if (imageInput.files.length > 0) {
                alert("Image selected: " + imageInput.files[0].name);
            }
        });
    }


    window.addEventListener('dragover', (e) => {
        e.preventDefault();
        document.body.style.border = "4px dashed #7289da";
    });

    window.addEventListener('dragleave', (e) => {
        e.preventDefault();
        document.body.style.border = "none";
    });

    window.addEventListener('drop', (e) => {
        e.preventDefault();
        document.body.style.border = "none";
        

        if (e.dataTransfer.files.length > 0 && imageInput) {
            imageInput.files = e.dataTransfer.files;
            alert("Image added: " + e.dataTransfer.files[0].name);
        }
    });
});
