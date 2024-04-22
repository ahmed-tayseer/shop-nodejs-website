const deleteProduct = e => {
  const prodId = e.target.parentNode.querySelector('[name=productId]').value;
  const csrf = e.target.parentNode.querySelector('[name=_csrf]').value;

  const productElement = e.target.closest('article');

  fetch('/admin/product/' + prodId, {
    method: 'DELETE',
    headers: {
      'csrf-token': csrf,
    },
  })
    .then(result => {
      return result.json();
    })
    .then(data => {
      console.log(data);
      productElement.parentNode.removeChild(productElement);
    })
    .catch(err => {
      console.log(err);
    });
};

const btns = document.querySelectorAll('.btn-delete');
btns.forEach(btn => {
  btn.addEventListener('click', deleteProduct);
});
