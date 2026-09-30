let products=[];
let customers=[];
let cart=[];

const money=value=>"TSh "+Number(value||0).toLocaleString("en-TZ");

function el(id){return document.getElementById(id);}

function escapeHtml(value=""){
  return String(value)
    .replaceAll("&","&amp;")
    .replaceAll("<","&lt;")
    .replaceAll(">","&gt;")
    .replaceAll('"',"&quot;")
    .replaceAll("'","&#039;");
}

async function loadPos(){
  const [productsResponse, customersResponse] = await Promise.all([
    fetch("/api/products"),
    fetch("/api/customers")
  ]);

  products = await productsResponse.json();
  customers = await customersResponse.json();

  el("productSelect").innerHTML = products.length
    ? products.map(product =>
        '<option value="'+product.id+'">'+
        escapeHtml(product.name)+" · "+money(product.price)+" · stock "+product.stock+
        "</option>"
      ).join("")
    : '<option value="">No products in stock</option>';

  el("customerSelect").innerHTML =
    '<option value="">Walk-in Customer</option>'+
    customers.map(customer =>
      '<option value="'+customer.id+'">'+
      escapeHtml(customer.name)+(customer.phone ? " · "+escapeHtml(customer.phone) : "")+
      "</option>"
    ).join("");

  renderCart();
}

function addToCart(){
  const productId=Number(el("productSelect").value);
  const quantity=Math.max(1,Number(el("quantity").value||1));
  const product=products.find(item=>item.id===productId);

  if(!product) return message("Select a product.",true);

  const existing=cart.find(item=>item.id===productId);
  const nextQuantity=(existing?existing.quantity:0)+quantity;

  if(nextQuantity>product.stock){
    return message("Only "+product.stock+" units of "+product.name+" are available.",true);
  }

  if(existing) existing.quantity=nextQuantity;
  else cart.push({
    id:product.id,
    name:product.name,
    price:Number(product.price),
    quantity,
    stock:product.stock
  });

  el("quantity").value=1;
  message("");
  renderCart();
}

function removeFromCart(productId){
  cart=cart.filter(item=>item.id!==productId);
  renderCart();
}

function setQuantity(productId,value){
  const item=cart.find(row=>row.id===productId);
  if(!item) return;

  const quantity=Math.max(1,Number(value||1));
  if(quantity>item.stock){
    return message("Only "+item.stock+" units are available.",true);
  }

  item.quantity=quantity;
  renderCart();
}

function renderCart(){
  const body=el("cartBody");

  if(!cart.length){
    body.innerHTML='<tr><td colspan="5" class="muted">No items added yet.</td></tr>';
  }else{
    body.innerHTML=cart.map(item =>
      '<tr>'+
        '<td><strong>'+escapeHtml(item.name)+'</strong></td>'+
        '<td>'+money(item.price)+'</td>'+
        '<td><input style="max-width:82px" type="number" min="1" max="'+item.stock+'" value="'+item.quantity+'" onchange="setQuantity('+item.id+',this.value)"></td>'+
        '<td>'+money(item.price*item.quantity)+'</td>'+
        '<td><button type="button" class="link danger" onclick="removeFromCart('+item.id+')">Remove</button></td>'+
      '</tr>'
    ).join("");
  }

  const subtotal=cart.reduce((sum,item)=>sum+(item.price*item.quantity),0);
  const discount=Math.max(0,Number(el("discount").value||0));
  const appliedDiscount=Math.min(discount,subtotal);
  const total=subtotal-appliedDiscount;

  el("subtotal").textContent=money(subtotal);
  el("discountTotal").textContent=money(appliedDiscount);
  el("grandTotal").textContent=money(total);
}

async function completeSale(){
  if(!cart.length) return message("Add at least one product.",true);

  const payload={
    customerId:el("customerSelect").value ? Number(el("customerSelect").value) : null,
    paymentMethod:el("paymentMethod").value,
    discount:Number(el("discount").value||0),
    items:cart.map(item=>({productId:item.id,quantity:item.quantity}))
  };

  message("Saving sale...");

  try{
    const response=await fetch("/api/checkout",{
      method:"POST",
      headers:{"Content-Type":"application/json"},
      body:JSON.stringify(payload)
    });

    const data=await response.json();

    if(!response.ok || !data.success){
      throw new Error(data.message||"Unable to complete sale.");
    }

    window.location.href="/receipt/"+encodeURIComponent(data.invoice);
  }catch(error){
    message(error.message||String(error),true);
  }
}

function message(text="",error=false){
  const box=el("posMessage");
  box.textContent=text;
  box.className="result"+(error?" error":"");
}

document.addEventListener("DOMContentLoaded",()=>{
  el("discount").addEventListener("input",renderCart);
  loadPos().catch(error=>message(error.message||String(error),true));
});
