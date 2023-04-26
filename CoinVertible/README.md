# Analyse de la sécurité de CoinVertible (émis par Société Générale-FORGE), un stablecoin adossé à l'euro sur Ethereum

Société Générale-FORGE (SG-FORGE) a récemment présenté CoinVertible, un stablecoin adossée à l'euro et émis sur la blockchain publique Ethereum. Aidé par ChatGPT, voici quelques observations relatives au code source ([https://etherscan.deth.net/address/0xf7790914dc335b20aa19d7c9c9171e14e278a134](https://etherscan.deth.net/address/0xf7790914dc335b20aa19d7c9c9171e14e278a134)) :

## Risque de blocage des demandes d'approbation légitimes dans la fonction "approve" du contrat "SmartCoin"

Dans la fonction `approve` du contrat `SmartCoin`, il y a une vérification pour s'assurer qu'il n'y a pas de demande d'approbation en cours pour le même couple d'adresses. Cependant, cela pourrait potentiellement permettre à un attaquant de bloquer les demandes d'approbation légitimes en soumettant d'abord une demande d'approbation malveillante: 

Dans le contrat `SmartCoin`, la fonction `approve` ressemble à ceci :
```solidity
function approve(address _spender, uint256 _value) public returns (bool) {
    require(allowance[msg.sender][_spender] == 0 || _value == 0);
    allowance[msg.sender][_spender] = _value;
    emit Approval(msg.sender, _spender, _value);
    return true;
}
```
 La ligne `require(allowance[msg.sender][_spender] == 0 || _value == 0);` vérifie si la demande d'approbation en cours pour le même couple d'adresses est égale à zéro, ou si la valeur de la nouvelle demande d'approbation est égale à zéro. Cette condition pourrait permettre à un attaquant de bloquer des demandes d'approbation légitimes en soumettant une demande d'approbation malveillante avec une valeur non nulle.

Pour illustrer cela, supposons que Alice souhaite autoriser Bob à dépenser 100 tokens en son nom. Avant qu'Alice ne soumette sa demande d'approbation, un attaquant pourrait soumettre une demande d'approbation malveillante pour le couple d'adresses (Alice, Bob) avec une valeur non nulle (par exemple, 1 token). En conséquence, la condition `allowance[Alice][Bob] == 0` ne serait pas satisfaite lorsque Alice soumettrait sa demande d'approbation légitime, et la transaction serait rejetée.
  
##  Problème de réentrance dans les fonctions
  Dans les fonctions `withdraw`, `validateTransfer` et `validateApprove`, les événements `TransferValidated` et `ApproveValidated` sont émis après avoir effectué les transferts ou les approbations. Il est généralement recommandé d'émettre des événements avant d'effectuer des modifications d'état pour éviter les problèmes de réentrance.
Voici un exemple de code pour la fonction `withdraw` :
```Solidity
function withdraw(uint256 _amount) public {
    require(balanceOf[msg.sender] >= _amount);
    balanceOf[msg.sender] -= _amount;
    msg.sender.transfer(_amount);
    emit Withdraw(msg.sender, _amount);
}

```
 Dans ce code, l'utilisateur peut retirer un montant spécifié de tokens. Cependant, il y a un problème de réentrance ici : l'appel à `msg.sender.transfer(_amount)` est effectué avant que l'événement `Withdraw` ne soit émis. Si `msg.sender` est un contrat malveillant, il pourrait être programmé pour rappeler la fonction `withdraw` lors de la réception de l'Ether, ce qui entraînerait une récursion et éventuellement un épuisement des fonds du contrat.

Pour éviter ce problème, nous pouvons utiliser le modèle "checks-effects-interactions". Ce modèle consiste à effectuer toutes les vérifications en premier, à mettre à jour l'état du contrat ensuite, et enfin à interagir avec d'autres contrats ou à effectuer des transferts d'Ether. Voici un exemple de code modifié pour la fonction `withdraw` :
```Solidity
function withdraw(uint256 _amount) public {
    require(balanceOf[msg.sender] >= _amount);

    // Mise à jour de l'état du contrat (effects)
    balanceOf[msg.sender] -= _amount;

    // Émission de l'événement (effects)
    emit Withdraw(msg.sender, _amount);

    // Interaction avec d'autres contrats ou transferts d'Ether (interactions)
    (bool success, ) = msg.sender.call{value: _amount}("");
    require(success, "Transfer failed.");
}
```
Dans cette version, nous mettons d'abord à jour l'état du contrat et émettons l'événement `Withdraw`. Ensuite, nous utilisons la méthode `call` pour effectuer le transfert d'Ether au lieu de `transfer`. La méthode `call` est préférable ici car elle permet de gérer explicitement les erreurs de transfert.

En réorganisant le code de cette manière, nous réduisons le risque d'attaques de réentrance en suivant le modèle "checks-effects-interactions".
Voici un lien vers la documentation officielle de Solidity qui décrit le modèle "checks-effects-interactions" et explique comment l'utiliser pour prévenir les attaques de réentrance :

[https://solidity.readthedocs.io/en/latest/security-considerations.html#use-the-checks-effects-interactions-pattern](https://solidity.readthedocs.io/en/latest/security-considerations.html#use-the-checks-effects-interactions-pattern)

Cette documentation est une excellente ressource pour comprendre le modèle et les meilleures pratiques pour sécuriser les contrats intelligents en Solidity.   

##  Risque potentiel lié à l'utilisation de "unchecked" sans les vérifications de sécurité appropriées.
 L'utilisation de `unchecked` dans plusieurs endroits du code peut potentiellement entraîner des problèmes si les vérifications de sécurité appropriées ne sont pas effectuées. 

L'emploi du bloc `unchecked` permet de désactiver temporairement la vérification des erreurs d'arithmétique, ce qui peut être utile dans certains cas pour optimiser le coût en gaz. Toutefois, il peut également entraîner des problèmes si les erreurs d'arithmétique ne sont pas gérées correctement.
    
##  L'absence de vérification de dépassements d'entiers pour la variable "_engagedAmount" dans la fonction "_initiateTransfer".

  La fonction `_initiateTransfer` vérifie si la balance disponible est suffisante, mais elle ne vérifie pas les dépassements d'entiers pour la variable `_engagedAmount`. Cela pourrait potentiellement entraîner des problèmes si cette variable est manipulée de manière incorrecte.
    

## Risque de contournement du propriétaire dans la fonction "recall" permettant au registrar de transférer des jetons d'un compte vers son propre compte

 il existe un scénario où le registrar peut transférer des jetons d'un compte en contournant le propriétaire. Le registrar peut utiliser la fonction `recall` pour transférer des jetons d'un compte vers son compte.

La fonction `recall` est définie dans le contrat SmartCoin comme suit:

````Solidity
function recall(address _from, uint256 _amount)
    external
    override
    onlyRegistrar
    returns (bool)
{
    require(
        _availableBalance(_from) >= _amount, // _amount should not exceed balance minus engagedAmount amount
        "SmartCoin: transfer amount exceeds balance"
    );
    super._transfer(_from, registrar, _amount);
    return true;
}
````
La fonction `recall` permet au registrar de transférer des jetons d'un compte spécifié par `_from` vers le compte du registrar. La fonction vérifie d'abord si le solde disponible du compte `_from` est supérieur ou égal au montant à transférer. Si tel est le cas, elle effectue un transfert en utilisant la fonction `_transfer` héritée du contrat ERC20.

Il est important de noter que cette fonction est protégée par le modificateur `onlyRegistrar`, ce qui signifie qu'elle ne peut être appelée que par le compte du registrar. Cependant, cela soulève des préoccupations en matière de sécurité et de confiance, car le registrar a le pouvoir de transférer des jetons sans le consentement du propriétaire du compte. Il est essentiel de considérer les implications de cette fonction et de s'assurer que des mesures de sécurité appropriées sont en place pour protéger les utilisateurs et leurs fonds.


### Ces observations ne constituent pas une liste exhaustive des problèmes potentiels. 
