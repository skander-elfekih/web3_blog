# Analyse de la sécurité de CoinVertible (émis par Société Générale-FORGE), un stablecoin adossé à l'euro sur Ethereum

Société Générale-FORGE (SG-FORGE) a récemment présenté CoinVertible, un stablecoin adossée à l'euro et émis sur la blockchain publique Ethereum. Aidé par ChatGPT, voici quelques observations relatives au code source ([https://etherscan.deth.net/address/0xf7790914dc335b20aa19d7c9c9171e14e278a134](https://etherscan.deth.net/address/0xf7790914dc335b20aa19d7c9c9171e14e278a134)) :
Ces observations ne constituent pas une liste exhaustive des problèmes potentiels.
## Possible reentrancy vulnerability dans validateTransfer() 

 Dans les fonctions `validateTransfer` et `validateApprove`, les événements `TransferValidated` et `ApproveValidated` sont émis après avoir effectué les transferts ou les approbations. Il est généralement recommandé d'émettre des événements avant d'effectuer des modifications d'état pour éviter les problèmes de réentrance.

````Solidity
function  validateTransfer(bytes32  transferHash)
external onlyRegistrar returns (bool)
{
TransferRequest memory _transferRequest = _transfers[transferHash];
	if (_transferRequest.isTransferFrom) {
		if(!whitelist[_transferRequest.spender]){
		revert("Whitelist: address must be whitelisted");
		}
	}
require(_transferRequest.status != TransferStatus.Undefined,"SmartCoin: transferHash does not exist");

require(_transferRequest.status == TransferStatus.Created,"SmartCoin: Invalid transfer status");

_transfers[transferHash].status = TransferStatus.Validated;

unchecked {
_engagedAmount[_transferRequest.from] -= _transferRequest.value;
}

_safeTransfer(_transferRequest.from,_transferRequest.to,_transferRequest.value);

emit  TransferValidated(transferHash); // <---- Potential vulnerability
return  true;
}
````

Pour éviter ce problème, nous pouvons utiliser le modèle "checks-effects-interactions". Ce modèle consiste à effectuer toutes les vérifications en premier, à mettre à jour l'état du contrat ensuite, et enfin à interagir avec d'autres contrats ou à effectuer des transferts d'Ether. 

Voici un lien vers la documentation officielle de Solidity qui décrit le modèle "checks-effects-interactions" et explique comment l'utiliser pour prévenir les attaques de réentrance :

[https://solidity.readthedocs.io/en/latest/security-considerations.html#use-the-checks-effects-interactions-pattern](https://solidity.readthedocs.io/en/latest/security-considerations.html#use-the-checks-effects-interactions-pattern)

Cette documentation est une excellente ressource pour comprendre le modèle et les meilleures pratiques pour sécuriser les contrats intelligents en Solidity.   

## Possible integer overflow dans _engagedAmount 

Un dépassement de capacité peut se produire si un nombre entier dépasse la plage de valeurs possibles pour un type de données. Dans ce cas, si le montant engagé dans un transfert ou une approbation dépasse le solde du compte, cela peut entraîner un dépassement de capacité. Pour éviter cela, il est recommandé de vérifier le dépassement de capacité lors de la mise à jour du montant engagé.

````Solidity
mapping (address => uint256) private _engagedAmount;

function _initiateTransfer(address _recipient, uint256 _amount) private {
    require(_recipient != address(0), "SmartCoin: recipient is zero address");
    require(_amount > 0, "SmartCoin: amount is zero");

    uint256 senderBalance = _balances[msg.sender];
    require(senderBalance >= _amount, "SmartCoin: insufficient balance");

    uint256 engagedAmount = _engagedAmount[msg.sender];
    _engagedAmount[msg.sender] = engagedAmount + _amount;  // <---- Potential vulnerability

    // Transfer tokens to recipient
    _balances[msg.sender] = senderBalance - _amount;
    _balances[_recipient] += _amount;

    emit Transfer(msg.sender, _recipient, _amount);
}
````

Pour éviter cette vulnérabilité potentielle, il est recommandé de réaliser une vérification d'overflow avant de mettre à jour la variable `_engagedAmount`. Par exemple, on peut ajouter une vérification comme celle-ci avant d'ajouter la valeur `_value` à la variable `_engagedAmount[_from]` :
````
require(_engagedAmount[_from] + _value >= _engagedAmount[_from], "SmartCoin: integer overflow");
````
Cette vérification s'assure que l'addition de `_value` avec la valeur actuelle de `_engagedAmount[_from]` ne dépasse pas la capacité maximale d'un entier uint256. Si cette vérification échoue, la fonction lance une exception et l'exécution s'arrête, empêchant ainsi une attaque par dépassement d'entier.

## Possible underflow dans recall() and burn() 

Un underflow peut se produire lorsque la soustraction d'un nombre plus grand à un nombre plus petit dépasse la plage de valeurs possibles pour un type de données. Dans ce cas, si le montant à transférer ou à brûler est supérieur au solde disponible, il peut y avoir un underflow. 

Pour éviter cela, il est recommandé de vérifier que le montant à transférer ou à brûler est inférieur ou égal au solde disponible.

````Solidity
function recall(address _recipient, uint256 _amount) public onlyOwner {
    require(_recipient != address(0), "SmartCoin: recipient is zero address");
    require(_amount > 0, "SmartCoin: amount is zero");

    uint256 availableBalance = _availableBalance(msg.sender);
    require(availableBalance >= _amount, "SmartCoin: insufficient balance");

    // Update balances
    _balances[msg.sender] -= _amount;
    _balances[_recipient] += _amount;

    emit Transfer(msg.sender, _recipient, _amount);
}

function burn(uint256 _amount) public {
    require(_amount > 0, "SmartCoin: amount is zero");

    uint256 availableBalance = _availableBalance(msg.sender);
    require(availableBalance >= _amount, "SmartCoin: insufficient balance");

    // Update balances
    _balances[msg.sender] -= _amount;
    _totalSupply -= _amount;

    emit Transfer(msg.sender, address(0), _amount);
}
````

## Possible front-running vulnerability dans approve() 

Le "front-running" se produit lorsqu'un attaquant utilise une transaction avec un prix du gaz plus élevé pour remplacer une transaction en attente d'un autre utilisateur, avant que la transaction originale ne soit traitée. Dans ce cas, cela peut se produire si un attaquant initie sa propre approbation pour le même dépensier avec un prix du gaz plus élevé avant que la transaction originale ne soit traitée. 

````Solidity
mapping (address => mapping (address => bool)) private _hasOngoingApprove;

function approve(address _spender, uint256 _amount) public returns (bool) {
    require(_spender != address(0), "SmartCoin: spender is zero address");

    // Prevent multiple ongoing approvals for the same spender
    require(!_hasOngoingApprove[msg.sender][_spender], "SmartCoin: ongoing approval");

    _hasOngoingApprove[msg.sender][_spender] = true;

    // Perform the approval
    _approve(msg.sender, _spender, _amount);

    // Clear the ongoing approval flag
    _hasOngoingApprove[msg.sender][_spender] = false;

    return true;
}
````

Voici un exemple de scénario:

1.  Un propriétaire de SmartCoin souhaite approuver un autre compte, appelons-le le compte "A", pour dépenser un certain montant de SmartCoin.
2.  Le propriétaire soumet une transaction pour approuver "A" avec un certain prix du gaz (gas price).
3.  Un attaquant voit cette transaction en attente dans le pool de transactions non confirmées et soumet sa propre transaction avec un prix du gaz plus élevé pour approuver "A" avec un montant différent.
4.  Les mineurs confirment la transaction de l'attaquant en premier, en remplaçant ainsi la transaction originale du propriétaire.

Ainsi, l'approbation originale du propriétaire a été remplacée par celle de l'attaquant. Cela peut être particulièrement problématique si le montant approuvé est important, car cela peut entraîner des pertes financières importantes pour le propriétaire.

Pour éviter cela, il est recommandé d'utiliser une approche basée sur un nonce pour prévenir ce type d'attaque.
Voici un exemple de code modifié de la fonction `approve()` pour utiliser une approche basée sur les numéros de séquence (nonce) :

````Solidity
mapping(address => mapping(uint256 => bool)) private _approvedNonces;

function approve(address _spender, uint256 _value, uint256 _nonce) public returns (bool) {
    require(_spender != address(0), "SmartCoin: cannot approve to zero address");
    require(_nonce > _approvedNonces[msg.sender][_spender], "SmartCoin: nonce must be greater than previous nonce");
    
    _approvedNonces[msg.sender][_spender] = _nonce;
    _allowances[msg.sender][_spender] = _value;
    
    emit Approval(msg.sender, _spender, _value);
    return true;
}
````

Dans ce code, la variable `_approvedNonces` est un mapping qui stocke le dernier numéro de séquence (nonce) approuvé pour chaque adresse de propriétaire et chaque adresse de dépenseur. Lorsqu'un propriétaire souhaite approuver une dépense avec une nouvelle valeur, il doit spécifier un nonce supérieur à celui de la dernière approbation pour cette paire propriétaire-dépenseur.

En utilisant cette approche, un attaquant ne peut pas simplement remplacer une approbation existante en soumettant une transaction avec un gas price plus élevé. Il doit connaître le nonce précédent pour soumettre une transaction valide, ce qui rend l'attaque beaucoup plus difficile.

	la transaction n'a pas besoin d'avoir le même expéditeur (sender) et destinataire (receiver) pour qu'une vulnérabilité de front-running puisse se produire. La vulnérabilité est liée au contenu de la transaction et à sa séquence dans le pool de transactions en attente. Si une transaction est publiée avec des paramètres identiques à une transaction en attente, mais avec des frais de gaz plus élevés, elle sera traitée en premier par les mineurs et remplacera la transaction initiale, même si les expéditeurs et les destinataires sont différents. C'est pourquoi il est important de concevoir des contrats intelligents en tenant compte de cette vulnérabilité et d'adopter des mécanismes de protection appropriés, tels que l'utilisation de nonces ou la définition de délais de blocage pour les transactions.

## Possible denial-of-service dans transferFrom() 

Dans la fonction _transferFrom(), la fonction _spendAllowance() est utilisée pour mettre à jour la somme allouée avant d'initier le transfert. Cependant, cette fonction ne vérifie pas si la somme allouée est suffisante pour effectuer le transfert, ce qui peut entraîner une attaque de déni de service si un utilisateur approuve un propriétaire pour une grande somme d'argent puis initie un transfert avec une somme beaucoup plus petite, bloquant ainsi les fonds du propriétaire. Il est recommandé d'effectuer une vérification supplémentaire pour le montant alloué.
    
````Solidity
function  transferFrom(
address  _from,
address  _to,
uint256  _value
)
public override(ERC20, ISmartCoin)
onlyWhitelisted(_msgSender())
onlyWhitelisted(_from)
onlyWhitelisted(_to)
returns (bool)
{
unchecked {super._spendAllowance(_from, _msgSender(), _value); }
_initiateTransfer(_from,_to,_value,true, _msgSender());
return  true;
}
````

## Risque potentiel lié à l'utilisation de "unchecked" sans les vérifications de sécurité appropriées.

L'utilisation de `unchecked` dans plusieurs endroits du code peut potentiellement entraîner des problèmes si les vérifications de sécurité appropriées ne sont pas effectuées.

L'emploi du bloc `unchecked` permet de désactiver temporairement la vérification des erreurs d'arithmétique, ce qui peut être utile dans certains cas pour optimiser le coût en gaz. Toutefois, il peut également entraîner des problèmes si les erreurs d'arithmétique ne sont pas gérées correctement.

## Risque de contournement du propriétaire dans la fonction "recall" permettant au registrar de transférer des jetons d'un compte vers son propre compte

il existe un scénario où le registrar peut transférer des jetons d'un compte en contournant le propriétaire. Le registrar peut utiliser la fonction `recall` pour transférer des jetons d'un compte vers le compte du registrar.

La fonction `recall` est définie dans le contrat SmartCoin comme suit:

````Solidity

function recall(address _from, uint256 _amount)
external override onlyRegistrar returns (bool)
{
require(_availableBalance(_from) >= _amount, // _amount should not exceed balance minus engagedAmount amount
"SmartCoin: transfer amount exceeds balance");
super._transfer(_from, registrar, _amount);
return true;
}
````

La fonction `recall` permet au registrar de transférer des jetons d'un compte spécifié par `_from` vers le compte du registrar. La fonction vérifie d'abord si le solde disponible du compte `_from` est supérieur ou égal au montant à transférer. Si tel est le cas, elle effectue un transfert en utilisant la fonction `_transfer` héritée du contrat ERC20.

Il est important de noter que cette fonction est protégée par le modificateur `onlyRegistrar`, ce qui signifie qu'elle ne peut être appelée que par le compte du registrar. Cependant, cela soulève des préoccupations en matière de sécurité et de confiance, car le registrar a le pouvoir de transférer des jetons sans le consentement du propriétaire du compte. Il est essentiel de considérer les implications de cette fonction et de s'assurer que des mesures de sécurité appropriées sont en place pour protéger les utilisateurs et leurs fonds.

## Pour conclure...

La sécurité est un élément crucial pour les contrats intelligents. Il est donc important d'être vigilant et de mettre en place des mesures de sécurité solides pour protéger les fonds des utilisateurs.

Dans le cas de SmartCoin, l'idée qu'un front-runner puisse simplement remplacer une approbation existante en payant des frais de transaction plus élevés peut sembler un peu absurde. Mais c'est précisément ce genre de vulnérabilités qui peuvent coûter des millions d'euros aux utilisateurs de contrats intelligents.
